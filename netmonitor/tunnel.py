"""Tunnel core integration for NetMonitor.

Discovers tunnel proxy configs, checks process/port status, queries the tunnel
Stats API for per-inbound and per-user traffic, and feeds anomalies into the
daemon's alert/webhook system.

Security:
- All Stats API calls are to localhost only.
- No secrets are logged.
- Config files are read-only.
"""

import json
import os
import re
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests

# Common tunnel config locations
TUNNEL_CONFIG_PATHS = [
    "/usr/local/etc/tunnel/config.json",
    "/etc/tunnel/config.json",
    "/etc/tunnel/config.jsonc",
    "/usr/local/etc/tunnel/config.jsonc",
    Path.home() / ".tunnel" / "config.json",
]

# Common tunnel binary locations
TUNNEL_BINARY_PATHS = [
    "/usr/local/bin/tunnel",
    "/usr/bin/tunnel",
    "/opt/tunnel/tunnel",
    "tunnel",
]

STATS_API_HOST = "127.0.0.1"
STATS_API_PORT = 10085
STATS_API_URL = f"http://{STATS_API_HOST}:{STATS_API_PORT}/debug/vars"


def find_tunnel_config() -> Optional[Path]:
    """Locate a tunnel config file on disk."""
    for p in TUNNEL_CONFIG_PATHS:
        path = Path(p)
        if path.is_file():
            return path
    return None


def find_tunnel_binary() -> Optional[str]:
    """Locate the tunnel binary."""
    for p in TUNNEL_BINARY_PATHS:
        try:
            result = subprocess.run(
                [p, "-version"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                return p
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            continue
    return None


def parse_tunnel_config(path: Path) -> Dict[str, Any]:
    """Parse a tunnel config JSON/JSONC file.

    Strips // and /* */ comments before parsing.
    """
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        return {"error": f"Cannot read config: {exc}"}

    # Remove line comments
    raw = re.sub(r"//.*", "", raw)
    # Remove block comments
    raw = re.sub(r"/\*.*?\*/", "", raw, flags=re.DOTALL)

    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        return {"error": f"Invalid JSON in config: {exc}"}


def extract_inbounds(config: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Extract inbound listener info from parsed tunnel config."""
    inbounds = config.get("inbounds", [])
    if not isinstance(inbounds, list):
        return []

    result: List[Dict[str, Any]] = []
    for ib in inbounds:
        if not isinstance(ib, dict):
            continue
        result.append(
            {
                "tag": ib.get("tag", "untagged"),
                "protocol": ib.get("protocol", "unknown"),
                "port": ib.get("port"),
                "listen": ib.get("listen", "0.0.0.0"),
                "streamSettings": ib.get("streamSettings", {}),
                "settings": ib.get("settings", {}),
            }
        )
    return result


def extract_outbounds(config: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Extract outbound info from parsed tunnel config."""
    outbounds = config.get("outbounds", [])
    if not isinstance(outbounds, list):
        return []

    result: List[Dict[str, Any]] = []
    for ob in outbounds:
        if not isinstance(ob, dict):
            continue
        result.append(
            {
                "tag": ob.get("tag", "untagged"),
                "protocol": ob.get("protocol", "unknown"),
                "settings": ob.get("settings", {}),
            }
        )
    return result


def tunnel_process_status() -> Dict[str, Any]:
    """Check whether a tunnel process is running and what ports it listens on."""
    from .network import get_connections, listening_ports

    import psutil

    tunnel_proc = None
    for proc in psutil.process_iter(["pid", "name", "cmdline"]):
        try:
            name = (proc.info.get("name") or "").lower()
            cmdline_list = proc.info.get("cmdline") or []
            if not cmdline_list:
                continue
            # Match if the executable name is tunnel
            exe = os.path.basename(cmdline_list[0]).lower()
            is_tunnel_binary = exe == "tunnel" or exe.endswith("tunnel.exe") or name == "tunnel"
            # Match if tunnel appears as a path component
            is_tunnel_path = any(
                "tunnel" in c.lower()
                and not c.lower().endswith(".py")
                and not c.lower().endswith(".md")
                and "/netmonitor/" not in c.lower()
                for c in cmdline_list
            )
            if is_tunnel_binary or is_tunnel_path:
                tunnel_proc = {
                    "pid": proc.info["pid"],
                    "name": proc.info["name"],
                    "cmdline": " ".join(cmdline_list)[:200],
                }
                break
        except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
            continue

    # Check listening ports commonly used by tunnel
    listeners = listening_ports()
    tunnel_ports = [
        c for c in listeners
        if c["local"] and any(
            port_str in c["local"]
            for port_str in (":443", ":8080", ":8443", ":2053", ":2087", ":10085")
        )
    ]

    return {
        "running": tunnel_proc is not None,
        "process": tunnel_proc,
        "listening_ports": tunnel_ports,
    }


def query_stats_api() -> Dict[str, Any]:
    """Query tunnel's expvar/Stats API over HTTP (localhost only).

    Returns cumulative traffic stats per inbound/outbound/user.
    """
    try:
        resp = requests.get(STATS_API_URL, timeout=5)
        resp.raise_for_status()
        data = resp.json()
        stats = data.get("stats", {})
        return {
            "inbound": stats.get("inbound", {}),
            "outbound": stats.get("outbound", {}),
            "user": stats.get("user", {}),
            "observatory": data.get("observatory", {}),
        }
    except requests.RequestException as exc:
        return {"error": f"Stats API unreachable: {exc}"}
    except (ValueError, KeyError) as exc:
        return {"error": f"Failed to parse stats: {exc}"}


def query_stats_via_cli(binary: str) -> Dict[str, Any]:
    """Fallback: query tunnel stats via the `tunnel api statsquery` CLI."""
    try:
        result = subprocess.run(
            [binary, "api", "statsquery", f"-s {STATS_API_HOST}:{STATS_API_PORT}"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode != 0:
            return {"error": f"statsquery failed: {result.stderr[:200]}"}
        return {"raw": result.stdout[:2000]}
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
        return {"error": f"statsquery error: {exc}"}


def get_tunnel_overview() -> Dict[str, Any]:
    """Gather a complete tunnel overview: config, process, ports, stats."""
    config_path = find_tunnel_config()
    config = {}
    inbounds = []
    outbounds = []

    if config_path:
        config = parse_tunnel_config(config_path)
        if "error" not in config:
            inbounds = extract_inbounds(config)
            outbounds = extract_outbounds(config)

    process = tunnel_process_status()
    stats = query_stats_api()
    if "error" in stats:
        binary = find_tunnel_binary()
        if binary:
            stats = query_stats_via_cli(binary)

    return {
        "timestamp": datetime.now().isoformat(),
        "config_path": str(config_path) if config_path else None,
        "config": config if "error" not in config else {"error": config.get("error")},
        "inbounds": inbounds,
        "outbounds": outbounds,
        "process": process,
        "stats": stats,
    }


def detect_tunnel_anomalies(
    overview: Dict[str, Any],
    known_countries: List[str],
) -> List[str]:
    """Detect anomalies: tunnel down, missing ports, geo anomalies in stats.

    Returns a list of human-readable alert strings.
    """
    alerts: List[str] = []

    process = overview.get("process", {})
    if not process.get("running"):
        alerts.append("🔴 TUNNEL DOWN: tunnel core process is not running")
        return alerts

    # Check if expected inbound ports are actually listening
    listening = process.get("listening_ports", [])
    listening_local = {c["local"] for c in listening}
    for ib in overview.get("inbounds", []):
        port = ib.get("port")
        if port is None:
            continue
        expected = f"0.0.0.0:{port}"
        alt = f":::{port}"
        if expected not in listening_local and alt not in listening_local:
            alerts.append(
                f"🔴 PORT DOWN: Tunnel inbound '{ib['tag']}' ({ib['protocol']}) "
                f"configured on port {port} but not listening"
            )

    # Stats-based anomaly
    stats = overview.get("stats", {})
    if "error" in stats:
        alerts.append("⚠️ TUNNEL STATS: Stats API unreachable — enable StatsService in config")

    return alerts


# --------------------------------------------------------------------------- #
# CLI-friendly formatting
# --------------------------------------------------------------------------- #
def format_overview(overview: Dict[str, Any]) -> str:
    """Format tunnel overview as a human-readable string."""
    lines: List[str] = []

    proc = overview.get("process", {})
    if proc.get("running"):
        p = proc.get("process", {})
        lines.append(f"[green]✓ Tunnel running[/green] (PID {p.get('pid')})")
    else:
        lines.append("[red]✗ Tunnel not running[/red]")

    inbounds = overview.get("inbounds", [])
    if inbounds:
        lines.append(f"\n[bold]Inbounds ({len(inbounds)}):[/bold]")
        for ib in inbounds:
            lines.append(
                f"  • {ib['tag']} — {ib['protocol']} — {ib['listen']}:{ib['port']}"
            )

    outbounds = overview.get("outbounds", [])
    if outbounds:
        lines.append(f"\n[bold]Outbounds ({len(outbounds)}):[/bold]")
        for ob in outbounds:
            lines.append(f"  • {ob['tag']} — {ob['protocol']}")

    stats = overview.get("stats", {})
    if "error" not in stats:
        inbound_stats = stats.get("inbound", {})
        if inbound_stats:
            lines.append("\n[bold]Inbound Traffic:[/bold]")
            for tag, data in list(inbound_stats.items())[:10]:
                up = data.get("uplink", 0)
                down = data.get("downlink", 0)
                lines.append(f"  {tag}: ↑{up:,} ↓{down:,}")

    return "\n".join(lines) if lines else "No tunnel data available."
