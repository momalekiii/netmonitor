"""Interactive CLI entry point built with Typer + Rich.

Hardening:
- Input validation on all user-provided values.
- No secrets printed to stdout (masked).
- Path traversal protection on file arguments.
- Graceful degradation when psutil access is restricted.
"""

import json
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, IntPrompt, Prompt
from rich.table import Table

from .config import (
    BACKUPS_DIR, LOGS_DIR, load_config, save_config, _config_path,
    mask_secret, validate_webhook_url, validate_telegram_token,
)
from .export import backup, export_logs
from .intel import domain_details, geoip_lookup
from .monitor import NetMonitorDaemon, get_daemon
from .network import (
    active_vpn_summary, check_port, detect_vpn, established_connections,
    get_adapters, get_connections, listening_ports,
)
from .security import (
    analyze_connections,
    block_ip,
    check_ssl_cert,
    compute_security_score,
    list_blocked,
    start_honeypot,
    unblock_ip,
)
from .tunnel import (
    detect_tunnel_anomalies,
    find_tunnel_binary,
    find_tunnel_config,
    format_overview,
    get_tunnel_overview,
    tunnel_process_status,
    query_stats_api,
)
from .webhooks import send_alert, test_webhooks
from .features import FEATURE_REGISTRY, get_available_features, load_feature

app = typer.Typer(
    name="netmonitor",
    help="Monitor network sockets, ports, adapters, VPNs, GeoIP & domain details. "
         "Run as a 24/7 daemon with `netmonitor daemon start`.",
    rich_markup_mode="rich",
)
console = Console()


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def _print_table(title: str, columns: list, rows: list) -> None:
    table = Table(title=title, show_lines=True)
    for col in columns:
        table.add_column(col, style="cyan", no_wrap=False)
    for row in rows:
        table.add_row(*[str(cell) for cell in row])
    console.print(table)


def _ask_webhook_config(config: dict) -> dict:
    console.print(Panel("[bold]Configure Webhooks[/bold]", style="magenta"))
    discord_url = Prompt.ask(
        "Discord webhook URL", default=config.get("discord_webhook_url", "")
    )
    if discord_url and not validate_webhook_url(discord_url):
        console.print("[yellow]⚠ Discord webhook URL looks invalid.[/yellow]")
    config["discord_webhook_url"] = discord_url

    telegram_token = Prompt.ask(
        "Telegram bot token", default=config.get("telegram_bot_token", "")
    )
    if telegram_token and not validate_telegram_token(telegram_token):
        console.print("[yellow]⚠ Telegram token looks invalid.[/yellow]")
    config["telegram_bot_token"] = telegram_token

    config["telegram_chat_id"] = Prompt.ask(
        "Telegram chat ID", default=config.get("telegram_chat_id", "")
    )
    config["alerts_enabled"] = Confirm.ask(
        "Enable alerts?", default=config.get("alerts_enabled", True)
    )
    save_config(config)
    console.print(
        f"[green]✓ Configuration saved.[/green] "
        f"(Discord: {mask_secret(config['discord_webhook_url'])}, "
        f"Telegram: {mask_secret(config['telegram_bot_token'])})"
    )
    return config


# --------------------------------------------------------------------------- #
# One-shot commands
# --------------------------------------------------------------------------- #
@app.command()
def ports(
    kind: str = typer.Option("inet", help="Connection family: inet, inet4, inet6, tcp, udp, unix, all"),
    status: Optional[str] = typer.Option(None, help="Filter by status (LISTEN, ESTABLISHED, ...)"),
    export: bool = typer.Option(False, "--export", help="Export results to file"),
) -> None:
    """List network sockets and ports."""
    conns = get_connections(kind=kind)
    if status:
        conns = [c for c in conns if c["status"].upper() == status.upper()]

    rows = [
        [
            c["local"], c["remote"], c["status"], c["type"], c["family"],
            str(c["pid"]), c["process"],
        ]
        for c in conns
    ]
    _print_table(
        f"Network Connections ({kind})",
        ["Local", "Remote", "Status", "Type", "Family", "PID", "Process"],
        rows,
    )
    console.print(f"\n[bold]Total:[/bold] {len(conns)}")

    if export:
        path = export_logs(conns, label="ports")
        console.print(f"[green]Exported to {path}[/green]")


@app.command()
def adapters() -> None:
    """List network adapters and interfaces."""
    adapters = get_adapters()
    rows = [
        [
            a["name"], a["status"], str(a["speed_mbps"]), str(a["mtu"]),
            a["duplex"], ", ".join(a["ips"]) if a["ips"] else "—",
            ", ".join(a["macs"]) if a["macs"] else "—",
            "YES" if a["is_vpn"] else "no",
        ]
        for a in adapters
    ]
    _print_table(
        "Network Adapters",
        ["Name", "Status", "Speed (Mbps)", "MTU", "Duplex", "IPs", "MACs", "Tunnel?"],
        rows,
    )


@app.command()
def vpn() -> None:
    """Detect active VPN / tunnel interfaces."""
    console.print(active_vpn_summary())
    vpns = detect_vpn()
    if vpns:
        rows = [
            [v["name"], v["status"], str(v["speed_mbps"]), ", ".join(v["ips"]) or "—"]
            for v in vpns
        ]
        _print_table(
            "VPN / Tunnel Interfaces",
            ["Name", "Status", "Speed (Mbps)", "IPs"],
            rows,
        )


@app.command()
def geoip(ip: Optional[str] = typer.Argument(None, help="IP address (omits = your public IP)")) -> None:
    """GeoIP lookup for an IP."""
    data = geoip_lookup(ip)
    if "error" in data:
        console.print(f"[red]Error: {data['error']}[/red]")
        raise typer.Exit(1)

    table = Table(title=f"GeoIP — {data.get('ip')}")
    for k, v in data.items():
        table.add_row(k.replace("_", " ").title(), str(v))
    console.print(table)

    if Confirm.ask("Send this to webhooks?", default=False):
        config = load_config()
        send_alert(
            config,
            f"GeoIP lookup for {data.get('ip')}\n```json\n{json.dumps(data, indent=2)}\n```",
            level="info",
        )


@app.command()
def domain(
    name: str = typer.Argument(..., help="Domain name"),
    whois: bool = typer.Option(True, "--whois/--no-whois", help="Include WHOIS data"),
) -> None:
    """Full domain/IP dossier: DNS + resolution + optional WHOIS."""
    data = domain_details(name)
    console.print(Panel(f"[bold]Domain Details — {name}[/bold]", style="blue"))

    res = data.get("resolution", {})
    console.print(f"[bold]Resolved IPs:[/bold] {', '.join(res.get('ips', [])) or 'none'}")
    for ip, rdns in res.get("reverse_dns", {}).items():
        console.print(f"  {ip} → {rdns}")

    dns = data.get("dns_records", {})
    dns_rows = [[rt, ", ".join(vals) if vals else "—"] for rt, vals in dns.items()]
    _print_table("DNS Records", ["Record", "Values"], dns_rows)

    if whois:
        w = data.get("whois", {})
        if "error" in w:
            console.print(f"[yellow]WHOIS error: {w['error']}[/yellow]")
        else:
            whois_rows = [
                ["Registrar", str(w.get("registrar") or "—")],
                ["Created", str(w.get("creation_date") or "—")],
                ["Expires", str(w.get("expiration_date") or "—")],
                ["Org", str(w.get("org") or "—")],
                ["Country", str(w.get("country") or "—")],
                ["Name Servers", ", ".join(w.get("name_servers") or []) or "—"],
            ]
            _print_table("WHOIS", ["Field", "Value"], whois_rows)

    if Confirm.ask("Send this to webhooks?", default=False):
        config = load_config()
        send_alert(
            config,
            f"Domain lookup for {name}\n```json\n{json.dumps(data, indent=2, default=str)}\n```",
            level="info",
        )


@app.command()
def check(port: int = typer.Argument(..., help="TCP port number to check")) -> None:
    """Check if a specific port is in use."""
    if port < 1 or port > 65535:
        console.print("[red]Port must be between 1 and 65535.[/red]")
        raise typer.Exit(1)
    found = check_port(port)
    if found:
        console.print(
            f"[green]Port {port} is IN USE[/green] by {found['process']} (PID {found['pid']}) "
            f"on {found['local']} → {found['remote']}"
        )
    else:
        console.print(f"[yellow]Port {port} is NOT in use.[/yellow]")


@app.command()
def export_logs_cmd(
    label: str = typer.Option("netmonitor", help="File name prefix"),
    fmt: str = typer.Option("json", help="json, csv, or txt"),
    path: Optional[str] = typer.Argument(None, help="Optional file/dir to back up instead of exporting logs"),
) -> None:
    """Export logs or create a backup."""
    if path:
        try:
            out = backup(path)
            console.print(f"[green]✓ Backup created: {out}[/green]")
        except (FileNotFoundError, ValueError) as exc:
            console.print(f"[red]{exc}[/red]")
            raise typer.Exit(1)
    else:
        data = {"exported_at": datetime.now().isoformat()}
        out = export_logs(data, label=label, fmt=fmt)
        console.print(f"[green]✓ Exported to {out}[/green]")


@app.command()
def backup_cmd(
    source: str = typer.Argument(..., help="File or directory to back up"),
    name: Optional[str] = typer.Option(None, "--name", help="Archive name"),
) -> None:
    """Create a ZIP backup of a file or directory."""
    try:
        out = backup(source, archive_name=name)
        console.print(f"[green]✓ Backup created: {out}[/green]")
    except (FileNotFoundError, ValueError) as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(1)


@app.command()
def webhook(
    test: bool = typer.Option(False, "--test", help="Send a test message"),
    message: Optional[str] = typer.Option(None, "--message", "-m", help="Message to send"),
    level: str = typer.Option("info", help="info, warning, error, success"),
) -> None:
    """Send alerts via configured Discord/Telegram webhooks."""
    config = load_config()
    if test:
        res = test_webhooks(config)
        console.print(json.dumps(res, indent=2))
        return
    if not message:
        console.print("[red]Provide --message or use --test[/red]")
        raise typer.Exit(1)
    res = send_alert(config, message, level=level)
    console.print(json.dumps(res, indent=2))


@app.command()
def config_cmd() -> None:
    """Interactive configuration for webhooks, alerts, and daemon settings."""
    cfg = load_config()
    _ask_webhook_config(cfg)
    cfg["interval"] = IntPrompt.ask("Poll interval (seconds)", default=cfg.get("interval", 60))
    cfg["api_enabled"] = Confirm.ask("Enable HTTP API?", default=cfg.get("api_enabled", False))
    if cfg["api_enabled"]:
        cfg["api_host"] = Prompt.ask("API host", default=cfg.get("api_host", "127.0.0.1"))
        cfg["api_port"] = IntPrompt.ask("API port", default=cfg.get("api_port", 8765))
    save_config(cfg)
    console.print("[green]✓ Configuration saved.[/green]")


@app.command()
def alerts() -> None:
    """Configure alert rules (port down/up, new connections, geo anomaly)."""
    cfg = load_config()
    rules = cfg.setdefault("alert_rules", {})
    console.print(Panel("[bold]Alert Rules[/bold]", style="magenta"))
    rules["port_down"] = Confirm.ask("Alert when a listening port goes down?", default=rules.get("port_down", True))
    rules["port_up"] = Confirm.ask("Alert when a new listening port appears?", default=rules.get("port_up", True))
    rules["new_connection"] = Confirm.ask("Alert on new connections?", default=rules.get("new_connection", True))
    rules["geo_anomaly"] = Confirm.ask("Alert on new countries (geo anomaly)?", default=rules.get("geo_anomaly", True))
    known = Prompt.ask("Known/safe countries (comma-separated codes, leave empty for any)", default=", ".join(rules.get("known_countries", [])))
    rules["known_countries"] = [c.strip().upper() for c in known.split(",") if c.strip()] if known else []
    save_config(cfg)
    console.print("[green]✓ Alert rules saved.[/green]")


# --------------------------------------------------------------------------- #
# Watch mode (live TUI)
# --------------------------------------------------------------------------- #
@app.command()
def watch(
    interval: int = typer.Option(5, "--interval", "-i", help="Refresh interval in seconds"),
    kind: str = typer.Option("inet", help="Connection family"),
) -> None:
    """Live refreshing view of connections and ports (like htop for sockets)."""
    if interval < 1 or interval > 3600:
        console.print("[red]Interval must be between 1 and 3600 seconds.[/red]")
        raise typer.Exit(1)

    console.print(f"[bold]Watch mode[/bold] — refreshing every {interval}s. Press Ctrl+C to stop.\n")

    try:
        while True:
            conns = get_connections(kind=kind)
            ports = listening_ports()

            conn_table = Table(title="Connections", show_lines=False)
            for col in ["Local", "Remote", "Status", "Type", "PID", "Process"]:
                conn_table.add_column(col, style="cyan")
            for c in conns[:50]:
                conn_table.add_row(
                    c["local"], c["remote"], c["status"], c["type"],
                    str(c["pid"]), c["process"],
                )

            port_table = Table(title="Listening Ports", show_lines=False)
            for col in ["Local", "Remote", "Process"]:
                port_table.add_column(col, style="green")
            for p in ports[:20]:
                port_table.add_row(p["local"], p["remote"], p["process"])

            console.clear()
            console.print(
                Panel(f"NetMonitor Watch — {kind} — {len(conns)} connections, {len(ports)} listening", style="blue")
            )
            console.print(conn_table)
            console.print("")
            console.print(port_table)
            time.sleep(interval)
    except KeyboardInterrupt:
        console.print("\n[bold]Watch stopped.[/bold]")


# --------------------------------------------------------------------------- #
# Daemon mode (24/7 background)
# --------------------------------------------------------------------------- #
@app.command()
def daemon(
    action: str = typer.Argument("start", help="start, stop, or status"),
    interval: Optional[int] = typer.Option(None, "--interval", "-i", help="Poll interval in seconds"),
) -> None:
    """Run netmonitor as a 24/7 background daemon with change detection & alerts."""
    config = load_config()
    if interval is not None:
        if interval < 5 or interval > 86400:
            console.print("[red]Interval must be between 5 and 86400 seconds.[/red]")
            raise typer.Exit(1)
        config["interval"] = interval

    daemon = get_daemon(config)

    if action == "start":
        if daemon.running:
            console.print("[yellow]Daemon is already running.[/yellow]")
            return
        daemon.start()
        console.print(
            f"[green]✓ Daemon started (interval={config['interval']}s). "
            f"Logs: {LOGS_DIR}[/green]"
        )
    elif action == "stop":
        daemon.stop()
        console.print("[yellow]Daemon stopped.[/yellow]")
    elif action == "status":
        state = "running" if daemon.running else "stopped"
        console.print(f"[bold]Daemon:[/bold] {state}")
        console.print(f"[bold]Interval:[/bold] {config.get('interval', 60)}s")
        console.print(f"[bold]Alerts:[/bold] {'on' if config.get('alerts_enabled') else 'off'}")
        console.print(f"[bold]API:[/bold] {'on' if config.get('api_enabled') else 'off'}")
    else:
        console.print("[red]Use: start, stop, or status[/red]")
        raise typer.Exit(1)


@app.command()
def api(
    host: str = typer.Option("127.0.0.1", help="API bind host (localhost recommended)"),
    port: int = typer.Option(8765, help="API bind port"),
) -> None:
    """Start the HTTP API server (exposes /status, /ports, /connections, /geoip, /domain)."""
    if port < 1024 or port > 65535:
        console.print("[red]Port must be between 1024 and 65535.[/red]")
        raise typer.Exit(1)

    try:
        from .api import run_api
    except ImportError:
        console.print("[red]FastAPI/uvicorn not installed. Run: pip install fastapi uvicorn slowapi[/red]")
        raise typer.Exit(1)

    config = load_config()
    config["api_enabled"] = True
    config["api_host"] = host
    config["api_port"] = port
    save_config(config)
    console.print(f"[green]✓ API server starting on http://{host}:{port}[/green]")
    run_api(host=host, port=port)


# --------------------------------------------------------------------------- #
# Security commands
# --------------------------------------------------------------------------- #
@app.command()
def security_scan(
    auto_block: bool = typer.Option(True, "--auto-block/--no-auto-block", help="Auto-block threatening IPs"),
) -> None:
    """Scan current connections for port scans, brute-force, and anomalies."""
    config = load_config()
    config["alerts_enabled"] = auto_block
    conns = get_connections()
    report = analyze_connections(conns, config)

    console.print(f"[bold]Security Scan[/bold] — {report['total_connections']} connections, {report['unique_remote_ips']} unique IPs")
    if report["threat_count"] == 0:
        console.print("[green]✓ No threats detected[/green]")
    else:
        console.print(f"[red]⚠ {report['threat_count']} threat(s) detected[/red]")
        for t in report["threats"]:
            sev_color = {"high": "red", "medium": "yellow", "info": "blue"}.get(t["severity"], "white")
            console.print(f"  [{sev_color}]{t['severity'].upper()}[/{sev_color}] {t['type']}: {t['detail']} (IP: {t['ip']})")

    if report["auto_blocked"]:
        console.print(f"\n[green]✓ Auto-blocked {len(report['auto_blocked'])} IP(s)[/green]")
        for ip in report["auto_blocked"]:
            console.print(f"  {ip}")


@app.command()
def security_block(
    ip: str = typer.Argument(..., help="IP address to block"),
    comment: str = typer.Option("netmonitor", help="Comment for the block rule"),
) -> None:
    """Block an IP address via firewall (nftables/iptables)."""
    if not _is_valid_ip_cli(ip):
        console.print(f"[red]Invalid IP: {ip}[/red]")
        raise typer.Exit(1)
    res = block_ip(ip, comment)
    if res["ok"]:
        console.print(f"[green]✓ Blocked {ip} via {res['method']}[/green]")
    else:
        console.print(f"[red]✗ Failed to block {ip}: {res.get('error', 'unknown')}[/red]")


@app.command()
def security_unblock(
    ip: str = typer.Argument(..., help="IP address to unblock"),
) -> None:
    """Unblock an IP address."""
    if not _is_valid_ip_cli(ip):
        console.print(f"[red]Invalid IP: {ip}[/red]")
        raise typer.Exit(1)
    res = unblock_ip(ip)
    if res["ok"]:
        console.print(f"[green]✓ Unblocked {ip}[/green]")
    else:
        console.print(f"[red]✗ {res.get('error', 'unknown')}[/red]")


@app.command()
def security_blocked() -> None:
    """List all blocked IPs."""
    data = list_blocked()
    blocked = data.get("blocked", {})
    if not blocked:
        console.print("[green]No IPs blocked.[/green]")
        return
    rows = [
        [ip, info.get("blocked_at", "—"), info.get("comment", "—"), info.get("method", "—")]
        for ip, info in blocked.items()
    ]
    _print_table("Blocked IPs", ["IP", "Blocked At", "Comment", "Method"], rows)


@app.command()
def security_score() -> None:
    """Compute a security score (0-100) for this server."""
    config = load_config()
    adapters = get_adapters()
    conns = get_connections()
    vpns = detect_vpn()
    result = compute_security_score(adapters, conns, vpns, config)

    color = {"A": "green", "B": "green", "C": "yellow", "D": "red", "F": "red"}.get(result["grade"], "white")
    console.print(f"[bold]Security Score:[/bold] [{color}]{result['score']}/100 — Grade {result['grade']}[/{color}]")
    if result["findings"]:
        console.print("\n[bold]Findings:[/bold]")
        for f in result["findings"]:
            fcolor = {"high": "red", "medium": "yellow", "info": "blue"}.get(f["severity"], "white")
            console.print(f"  [{fcolor}]{f['severity'].upper()}[/{fcolor}] {f['issue']}: {f['detail']}")
    else:
        console.print("[green]✓ No issues found.[/green]")


@app.command()
def security_cert(
    domain: str = typer.Argument(..., help="Domain name"),
    port: int = typer.Option(443, help="Port"),
) -> None:
    """Check SSL/TLS certificate expiry for a domain."""
    if port < 1 or port > 65535:
        console.print("[red]Invalid port.[/red]")
        raise typer.Exit(1)
    result = check_ssl_cert(domain, port)
    if "error" in result:
        console.print(f"[red]{result['error']}[/red]")
        raise typer.Exit(1)

    days = result["days_left"]
    status = "🔴 EXPIRED" if result["expired"] else ("🟡 EXPIRING SOON" if result["expiring_soon"] else "🟢 OK")
    console.print(f"[bold]{domain}:{port}[/bold] — {status}")
    console.print(f"  Issuer: {result['issuer']}")
    console.print(f"  Subject: {result['subject']}")
    console.print(f"  Expires: {result['expires']}")
    console.print(f"  Days left: {days}")


@app.command()
def security_honeypot(
    ports: str = typer.Argument("2222,3333,4444", help="Comma-separated honeypot ports"),
    duration: int = typer.Option(60, "--duration", "-d", help="Seconds to run"),
) -> None:
    """Run honeypot listeners on fake ports; alert and block any connection."""
    port_list = []
    for p in ports.split(","):
        try:
            port_list.append(int(p.strip()))
        except ValueError:
            continue
    if not port_list:
        console.print("[red]No valid ports.[/red]")
        raise typer.Exit(1)
    if duration < 10 or duration > 3600:
        console.print("[red]Duration must be 10-3600 seconds.[/red]")
        raise typer.Exit(1)

    console.print(f"[bold]Honeypot[/bold] — listening on {port_list} for {duration}s...")
    console.print("[yellow]Ctrl+C to stop early.[/yellow]\n")
    try:
        result = start_honeypot(port_list, duration)
        console.print(f"\n[bold]Results:[/bold] {result['hit_count']} hit(s)")
        for h in result["hits"]:
            console.print(f"  Port {h['port']} — {h['ip']} at {h['time']}")
        if result["hit_count"] == 0:
            console.print("[green]✓ No connections to honeypot ports.[/green]")
    except KeyboardInterrupt:
        console.print("\n[bold]Honeypot stopped.[/bold]")


# --------------------------------------------------------------------------- #
# Feature management
# --------------------------------------------------------------------------- #
def _load_features_from_config(config: Dict[str, Any]) -> Dict[str, Any]:
    """Instantiate all registered features from config and attach to config dict."""
    features = {}
    for fname in FEATURE_REGISTRY:
        feat = load_feature(fname, config)
        if feat:
            features[fname] = feat
    config["_features"] = features
    return config


@app.command()
def features_cmd() -> None:
    """List and manage optional features."""
    config = load_config()
    _load_features_from_config(config)
    features = config.get("_features", {})

    console.print("[bold]Optional Features[/bold]")
    console.print("==================")
    for fname, feat in sorted(features.items()):
        status = "[green]enabled[/green]" if feat.is_enabled() else "[yellow]disabled[/yellow]"
        root = " (root required)" if feat.requires_root else ""
        console.print(f"  {fname}: {status}{root}")
        console.print(f"    {feat.description}")
    console.print()
    console.print("To enable/disable: edit ~/.netmonitor/config.yaml (or config.json)")
    console.print("Then restart: netmonitor daemon restart")


# --------------------------------------------------------------------------- #
# Tunnel commands
# --------------------------------------------------------------------------- #
@app.command()
def tunnel(
    detail: bool = typer.Option(False, "--detail", "-d", help="Show full config and stats JSON"),
) -> None:
    """Show tunnel core status, inbounds/outbounds, and traffic stats."""
    overview = get_tunnel_overview()
    console.print(format_overview(overview))

    if detail:
        console.print("\n[bold]Full overview (JSON):[/bold]")
        console.print_json(json.dumps(overview, indent=2, default=str))

    # Alerts
    config = load_config()
    known = config.get("alert_rules", {}).get("known_countries", [])
    alerts = detect_tunnel_anomalies(overview, known)
    if alerts:
        console.print("\n[red]⚠ Alerts:[/red]")
        for a in alerts:
            console.print(f"  {a}")
        if config.get("alerts_enabled", True):
            send_alert(config, "\n".join(alerts), level="warning")


@app.command()
def tunnel_status() -> None:
    """Check if tunnel core is running and which ports it listens on."""
    proc = tunnel_process_status()
    if proc["running"]:
        p = proc.get("process", {})
        console.print(f"[green]✓ Tunnel running[/green] (PID {p.get('pid')})")
        console.print(f"  cmdline: {p.get('cmdline', '')[:120]}")
    else:
        console.print("[red]✗ Tunnel not running[/red]")

    ports = proc.get("listening_ports", [])
    if ports:
        console.print("[bold]Listening ports:[/bold]")
        for c in ports:
            console.print(f"  {c['local']} → {c['remote']} ({c['process']})")
    else:
        console.print("[yellow]No tunnel listening ports detected.[/yellow]")


@app.command()
def tunnel_traffic() -> None:
    """Show per-inbound and per-user traffic from tunnel Stats API."""
    stats = query_stats_api()
    if "error" in stats:
        console.print(f"[red]{stats['error']}[/red]")
        binary = find_tunnel_binary()
        if binary:
            stats = query_stats_via_cli(binary)
            if "error" not in stats:
                console.print(stats.get("raw", ""))
        raise typer.Exit(1)

    inbound_stats = stats.get("inbound", {})
    outbound_stats = stats.get("outbound", {})
    user_stats = stats.get("user", {})

    if inbound_stats:
        rows = [
            [tag, str(d.get("uplink", 0)), str(d.get("downlink", 0))]
            for tag, d in inbound_stats.items()
        ]
        _print_table("Inbound Traffic", ["Tag", "Uplink (bytes)", "Downlink (bytes)"], rows)

    if outbound_stats:
        rows = [
            [tag, str(d.get("uplink", 0)), str(d.get("downlink", 0))]
            for tag, d in outbound_stats.items()
        ]
        _print_table("Outbound Traffic", ["Tag", "Uplink (bytes)", "Downlink (bytes)"], rows)

    if user_stats:
        rows = [
            [user, str(d.get("uplink", 0)), str(d.get("downlink", 0))]
            for user, d in list(user_stats.items())[:20]
        ]
        _print_table("User Traffic (top 20)", ["User", "Uplink (bytes)", "Downlink (bytes)"], rows)

    if not inbound_stats and not outbound_stats:
        console.print("[yellow]No traffic stats available. Enable StatsService in tunnel config.[/yellow]")


# --------------------------------------------------------------------------- #
# Feature management
# --------------------------------------------------------------------------- #
def _load_features_from_config(config: Dict[str, Any]) -> Dict[str, Any]:
    """Instantiate all registered features from config and attach to config dict."""
    features = {}
    for fname in FEATURE_REGISTRY:
        feat = load_feature(fname, config)
        if feat:
            features[fname] = feat
    config["_features"] = features
    return config


@app.command()
def features() -> None:
    """List and manage optional features."""
    config = load_config()
    _load_features_from_config(config)
    features = config.get("_features", {})

    console.print("[bold]Optional Features[/bold]")
    console.print("==================")
    for fname, feat in sorted(features.items()):
        status = "[green]enabled[/green]" if feat.is_enabled() else "[yellow]disabled[/yellow]"
        root = " (root required)" if feat.requires_root else ""
        console.print(f"  {fname}: {status}{root}")
        console.print(f"    {feat.description}")
    console.print()
    console.print("To enable/disable: edit ~/.netmonitor/config.yaml (or config.json)")
    console.print("Then restart: netmonitor daemon restart")


# --------------------------------------------------------------------------- #
# Interactive menu
# --------------------------------------------------------------------------- #
def _is_valid_ip_cli(ip: str) -> bool:
    try:
        import ipaddress
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def _interactive_menu() -> None:
    config = load_config()
    config = _load_features_from_config(config)
    while True:
        console.print(
            Panel(
                "[bold cyan]NetMonitor[/bold cyan] — 24/7 Network Monitor\n"
                f"v{__import__('netmonitor').__version__}  |  Daemon: "
                f"{'[green]RUNNING[/green]' if get_daemon().running else '[yellow]stopped[/yellow]'}"
                f"  |  Config: {_config_path().name}",
                style="blue",
            )
        )
        choices = {
            "1": ("Scan ports & sockets", _menu_ports),
            "2": ("Listening ports only", _menu_listening),
            "3": ("Network adapters", _menu_adapters),
            "4": ("Active VPNs", _menu_vpn),
            "5": ("Check a specific port", _menu_check_port),
            "6": ("GeoIP lookup", _menu_geoip),
            "7": ("Domain/IP details", _menu_domain),
            "8": ("Export logs", _menu_export),
            "9": ("Create backup", _menu_backup),
            "10": ("Send webhook alert", _menu_webhook),
            "11": ("Configure webhooks & alerts", lambda: _ask_webhook_config(config)),
            "12": ("Daemon start/stop/status", _menu_daemon),
            "13": ("Watch (live TUI)", _menu_watch),
            "14": ("Start API server", _menu_api),
            "15": ("Tunnel status & traffic", _menu_tunnel),
            "16": ("Security scan & score", _menu_security),
            "17": ("Optional features", _menu_features),
            "0": ("Exit", None),
        }
        for key, (label, _) in choices.items():
            console.print(f"[bold]{key}[/bold]. {label}")

        sel = Prompt.ask("\nSelect an option", choices=list(choices.keys()), default="0")
        if sel == "0":
            console.print("[bold]Goodbye![/bold]")
            break
        action = choices[sel][1]
        if action:
            action(config)
        console.print()


def _menu_ports(config: dict) -> None:
    conns = get_connections()
    rows = [
        [c["local"], c["remote"], c["status"], c["type"], str(c["pid"]), c["process"]]
        for c in conns
    ]
    _print_table("All Connections", ["Local", "Remote", "Status", "Type", "PID", "Process"], rows)
    console.print(f"[bold]Total:[/bold] {len(conns)}")
    if Confirm.ask("Export this list?", default=False):
        path = export_logs(conns, label="ports")
        console.print(f"[green]Saved to {path}[/green]")


def _menu_listening(config: dict) -> None:
    conns = listening_ports()
    rows = [[c["local"], c["remote"], c["process"]] for c in conns]
    _print_table("Listening Ports", ["Local", "Remote", "Process"], rows)
    console.print(f"[bold]Total listening:[/bold] {len(conns)}")


def _menu_adapters(config: dict) -> None:
    adapters = get_adapters()
    rows = [
        [a["name"], a["status"], str(a["speed_mbps"]), str(a["mtu"]),
         ", ".join(a["ips"]) or "—", "YES" if a["is_vpn"] else "no"]
        for a in adapters
    ]
    _print_table("Network Adapters", ["Name", "Status", "Speed", "MTU", "IPs", "Tunnel?"], rows)


def _menu_vpn(config: dict) -> None:
    console.print(active_vpn_summary())
    vpns = detect_vpn()
    if vpns and Confirm.ask("Send VPN status to webhooks?", default=False):
        send_alert(config, active_vpn_summary(), level="info")


def _menu_check_port(config: dict) -> None:
    port = IntPrompt.ask("Port number")
    if port < 1 or port > 65535:
        console.print("[red]Invalid port.[/red]")
        return
    found = check_port(port)
    if found:
        console.print(f"[green]Port {port} is IN USE[/green] by {found['process']} (PID {found['pid']})")
    else:
        console.print(f"[yellow]Port {port} is NOT in use.[/yellow]")


def _menu_geoip(config: dict) -> None:
    ip = Prompt.ask("IP address (leave blank for your public IP)", default="")
    data = geoip_lookup(ip or None)
    if "error" in data:
        console.print(f"[red]{data['error']}[/red]")
        return
    for k, v in data.items():
        console.print(f"[bold]{k.replace('_', ' ').title()}:[/bold] {v}")
    if Confirm.ask("Send to webhooks?", default=False):
        send_alert(config, f"GeoIP {data.get('ip')}\n```json\n{json.dumps(data, indent=2)}\n```", level="info")


def _menu_domain(config: dict) -> None:
    name = Prompt.ask("Domain name")
    data = domain_details(name)
    res = data.get("resolution", {})
    console.print(f"[bold]IPs:[/bold] {', '.join(res.get('ips', [])) or 'none'}")
    dns_rows = [
        [rt, ", ".join(vals) if vals else "—"]
        for rt, vals in data.get("dns_records", {}).items()
    ]
    _print_table("DNS Records", ["Record", "Values"], dns_rows)
    w = data.get("whois", {})
    if "error" not in w:
        whois_rows = [
            ["Registrar", str(w.get("registrar") or "—")],
            ["Created", str(w.get("creation_date") or "—")],
            ["Expires", str(w.get("expiration_date") or "—")],
        ]
        _print_table("WHOIS (summary)", ["Field", "Value"], whois_rows)
    if Confirm.ask("Send to webhooks?", default=False):
        send_alert(config, f"Domain {name}\n```json\n{json.dumps(data, indent=2, default=str)}\n```", level="info")


def _menu_export(config: dict) -> None:
    label = Prompt.ask("File name prefix", default="netmonitor")
    fmt = Prompt.ask("Format", choices=["json", "csv", "txt"], default="json")
    data = {"exported_at": datetime.now().isoformat()}
    path = export_logs(data, label=label, fmt=fmt)
    console.print(f"[green]✓ Exported to {path}[/green]")


def _menu_backup(config: dict) -> None:
    source = Prompt.ask("File or directory to back up")
    name = Prompt.ask("Archive name (optional)", default="")
    try:
        out = backup(source, archive_name=name or None)
        console.print(f"[green]✓ Backup created: {out}[/green]")
    except (FileNotFoundError, ValueError) as exc:
        console.print(f"[red]{exc}[/red]")


def _menu_webhook(config: dict) -> None:
    message = Prompt.ask("Message")
    level = Prompt.ask("Level", choices=["info", "warning", "error", "success"], default="info")
    res = send_alert(config, message, level=level)
    console.print(json.dumps(res, indent=2))


def _menu_daemon(config: dict) -> None:
    choice = Prompt.ask("start, stop, or status", choices=["start", "stop", "status"], default="status")
    interval = IntPrompt.ask("Poll interval (seconds)", default=config.get("interval", 60)) if choice == "start" else None
    if interval:
        config["interval"] = interval
        save_config(config)
    daemon = get_daemon(config)
    if choice == "start":
        if daemon.running:
            console.print("[yellow]Already running.[/yellow]")
        else:
            daemon.start()
            console.print(f"[green]✓ Daemon started ({interval}s interval).[/green]")
    elif choice == "stop":
        daemon.stop()
        console.print("[yellow]Daemon stopped.[/yellow]")
    else:
        console.print(f"Daemon: {'running' if daemon.running else 'stopped'}")


def _menu_watch(config: dict) -> None:
    interval = IntPrompt.ask("Refresh interval (seconds)", default=5)
    kind = Prompt.ask("Connection family", choices=["inet", "inet4", "inet6", "tcp", "udp", "unix", "all"], default="inet")
    console.print(f"[bold]Watch mode[/bold] — {interval}s. Ctrl+C to stop.")
    try:
        while True:
            conns = get_connections(kind=kind)
            ports = listening_ports()
            console.clear()
            console.print(Panel(f"NetMonitor Watch — {kind} — {len(conns)} connections, {len(ports)} listening", style="blue"))
            rows = [
                [c["local"], c["remote"], c["status"], c["type"], str(c["pid"]), c["process"]]
                for c in conns[:30]
            ]
            _print_table("Connections", ["Local", "Remote", "Status", "Type", "PID", "Process"], rows)
            time.sleep(interval)
    except KeyboardInterrupt:
        console.print("\n[bold]Watch stopped.[/bold]")


def _menu_api(config: dict) -> None:
    host = Prompt.ask("API host", default=config.get("api_host", "127.0.0.1"))
    port = IntPrompt.ask("API port", default=config.get("api_port", 8765))
    console.print(f"[green]Starting API on http://{host}:{port}[/green]")
    try:
        from .api import run_api
        run_api(host=host, port=port)
    except ImportError:
        console.print("[red]Install fastapi, uvicorn, and slowapi first: pip install fastapi uvicorn slowapi[/red]")


def _menu_tunnel(config: dict) -> None:
    overview = get_tunnel_overview()
    console.print(format_overview(overview))
    known = config.get("alert_rules", {}).get("known_countries", [])
    alerts = detect_tunnel_anomalies(overview, known)
    if alerts:
        console.print("\n[red]⚠ Alerts:[/red]")
        for a in alerts:
            console.print(f"  {a}")
        if Confirm.ask("Send tunnel alerts to webhooks?", default=False):
            send_alert(config, "\n".join(alerts), level="warning")


def _menu_features(config: dict) -> None:
    config = _load_features_from_config(config)
    features_cmd()


def _menu_security(config: dict) -> None:
    config = _load_features_from_config(config)
    conns = get_connections()
    report = analyze_connections(conns, config)
    console.print(f"[bold]Security Scan[/bold] — {report['total_connections']} connections")
    if report["threat_count"] == 0:
        console.print("[green]✓ No threats detected[/green]")
    else:
        for t in report["threats"]:
            console.print(f"  [red]{t['severity'].upper()}[/red] {t['type']}: {t['detail']} ({t['ip']})")

    # Run fail2ban scan if enabled
    features = config.get("_features", {})
    f2b = features.get("fail2ban")
    if f2b and f2b.is_enabled():
        f2b_report = f2b.scan_log()
        if "error" not in f2b_report and f2b_report.get("suspicious"):
            console.print("\n[red]⚠ Fail2Ban suspicious IPs:[/red]")
            for s in f2b_report["suspicious"]:
                console.print(f"  {s['ip']}: {s['count']} failed attempts")

    # Run uptime check if enabled
    up = features.get("uptime_monitor")
    if up and up.is_enabled():
        up_report = up.check_targets()
        if "error" not in up_report:
            down = [n for n, r in up_report.get("targets", {}).items() if not r.get("reachable")]
            if down:
                console.print("\n[red]⚠ Uptime targets down:[/red] " + ", ".join(down))

    score = compute_security_score(get_adapters(), conns, detect_vpn(), config)
    color = {"A": "green", "B": "green", "C": "yellow", "D": "red", "F": "red"}.get(score["grade"], "white")
    console.print(f"\n[bold]Security Score:[/bold] [{color}]{score['score']}/100 — {score['grade']}[/{color}]")


@app.command(name="interactive", hidden=True)
def _interactive_cmd() -> None:
    _interactive_menu()


@app.command()
def run() -> None:
    """Launch the interactive menu (default behavior)."""
    _interactive_menu()


if __name__ == "__main__":
    app()
