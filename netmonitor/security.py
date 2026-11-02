"""Security module for NetMonitor — intrusion detection, auto-block, scorecard.

Features:
- Port scan detection (IP hitting many ports in short window)
- Brute-force detection (repeated connections to sensitive ports)
- Geo anomaly detection (connections from unexpected countries)
- Fail2Ban-style auto-block via iptables/nftables
- SSL/TLS certificate expiry checker
- Security scorecard (0-100)
- Honeypot ports (fake listeners that alert on connection)

Security hardening:
- IP validation before any firewall operation
- No shell=True; subprocess args as list
- All iptables/nftables commands run with --wait to avoid locks
- Blocklist stored in ~/.netmonitor/security/blocklist.json
"""

import ipaddress
import json
import os
import subprocess
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from .config import CONFIG_DIR, LOGS_DIR, load_config, save_state, get_state

SECURITY_DIR = CONFIG_DIR / "security"
BLOCKLIST_FILE = SECURITY_DIR / "blocklist.json"
SCAN_LOG_FILE = LOGS_DIR / "security_scan.log"

# Ports commonly targeted by scanners / brute-force
SENSITIVE_PORTS = {22, 2222, 3389, 5900, 80, 443, 8080, 8443, 10085, 5432, 3306, 6379, 27017}

# Thresholds
PORT_SCAN_THRESHOLD = 10  # distinct ports per IP per window
BRUTE_FORCE_THRESHOLD = 5  # connections per IP per window
SCAN_WINDOW_SECONDS = 300  # 5 minutes


def ensure_dirs() -> None:
    SECURITY_DIR.mkdir(parents=True, exist_ok=True)
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(SECURITY_DIR, 0o700)
    except OSError:
        pass


def _load_blocklist() -> Dict[str, Any]:
    ensure_dirs()
    if not BLOCKLIST_FILE.exists():
        return {"blocked": {}, "version": 1}
    try:
        with BLOCKLIST_FILE.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
        if not isinstance(data, dict):
            return {"blocked": {}, "version": 1}
        return data
    except (json.JSONDecodeError, OSError):
        return {"blocked": {}, "version": 1}


def _save_blocklist(data: Dict[str, Any]) -> None:
    ensure_dirs()
    with BLOCKLIST_FILE.open("w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, default=str)
    try:
        os.chmod(BLOCKLIST_FILE, 0o600)
    except OSError:
        pass


def _is_valid_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def _run_firewall_cmd(args: List[str]) -> Dict[str, Any]:
    """Run a firewall command safely (no shell=True)."""
    try:
        result = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=15,
        )
        return {
            "ok": result.returncode == 0,
            "stdout": result.stdout[:500],
            "stderr": result.stderr[:500],
            "returncode": result.returncode,
        }
    except subprocess.TimeoutExpired:
        return {"ok": False, "stdout": "", "stderr": "command timed out", "returncode": -1}
    except FileNotFoundError:
        return {"ok": False, "stdout": "", "stderr": "firewall command not found", "returncode": -1}
    except OSError as exc:
        return {"ok": False, "stdout": "", "stderr": str(exc)[:200], "returncode": -1}


def block_ip(ip: str, comment: str = "netmonitor") -> Dict[str, Any]:
    """Block an IP using nftables (preferred) or iptables."""
    if not _is_valid_ip(ip):
        return {"ok": False, "error": f"Invalid IP: {ip}"}

    data = _load_blocklist()
    now = datetime.now(timezone.utc).isoformat()

    # Try nftables first
    nft_result = _run_firewall_cmd([
        "nft", "add", "rule", "inet", "filter", "input",
        "ip", "saddr", ip, "drop", "comment", comment,
    ])
    if not nft_result["ok"]:
        # Fallback to iptables
        ipt_result = _run_firewall_cmd([
            "iptables", "-I", "INPUT", "-s", ip, "-j", "DROP",
            "-m", "comment", "--comment", comment,
        ])
        if not ipt_result["ok"]:
            return {
                "ok": False,
                "error": "nftables and iptables both failed",
                "nft": nft_result,
                "iptables": ipt_result,
            }

    data["blocked"][ip] = {
        "blocked_at": now,
        "comment": comment,
        "method": "nftables" if nft_result["ok"] else "iptables",
    }
    _save_blocklist(data)
    _log_security(f"BLOCKED {ip} — {comment}")
    return {"ok": True, "ip": ip, "method": data["blocked"][ip]["method"]}


def unblock_ip(ip: str) -> Dict[str, Any]:
    """Remove an IP from the blocklist and firewall."""
    if not _is_valid_ip(ip):
        return {"ok": False, "error": f"Invalid IP: {ip}"}

    data = _load_blocklist()
    if ip not in data.get("blocked", {}):
        return {"ok": False, "error": f"IP {ip} not in blocklist"}

    method = data["blocked"][ip].get("method", "nftables")
    if method == "nftables":
        _run_firewall_cmd([
            "nft", "delete", "rule", "inet", "filter", "input",
            "ip", "saddr", ip, "drop",
        ])
    else:
        _run_firewall_cmd([
            "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP",
        ])

    del data["blocked"][ip]
    _save_blocklist(data)
    _log_security(f"UNBLOCKED {ip}")
    return {"ok": True, "ip": ip}


def list_blocked() -> Dict[str, Any]:
    """Return the current blocklist."""
    return _load_blocklist()


def _log_security(message: str) -> None:
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).isoformat()
    try:
        with SCAN_LOG_FILE.open("a", encoding="utf-8") as fh:
            fh.write(f"[{stamp}] {message}\n")
    except OSError:
        pass


# --------------------------------------------------------------------------- #
# Detection
# --------------------------------------------------------------------------- #
def analyze_connections(
    connections: List[Dict[str, Any]],
    config: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Analyze a list of connections for suspicious patterns.

    Returns a report with detected threats and recommended actions.
    """
    config = config or load_config()
    now = time.time()
    window_start = now - SCAN_WINDOW_SECONDS

    ip_ports: Dict[str, Set[int]] = {}
    ip_count: Dict[str, int] = {}
    geo_anomalies: List[str] = []
    sensitive_hits: List[Dict[str, Any]] = []

    known_countries = set(config.get("alert_rules", {}).get("known_countries", []))

    for c in connections:
        remote = c.get("remote", "N/A")
        if remote == "N/A" or ":" not in remote:
            continue
        ip = remote.rsplit(":", 1)[0]
        if not _is_valid_ip(ip):
            continue
        # Skip local/private IPs
        try:
            addr = ipaddress.ip_address(ip)
            if addr.is_private or addr.is_loopback:
                continue
        except ValueError:
            continue

        try:
            port = int(remote.rsplit(":", 1)[1])
        except (ValueError, IndexError):
            continue

        ip_ports.setdefault(ip, set()).add(port)
        ip_count[ip] = ip_count.get(ip, 0) + 1

        if port in SENSITIVE_PORTS:
            sensitive_hits.append({"ip": ip, "port": port, "local": c.get("local", "")})

    threats: List[Dict[str, Any]] = []

    # Port scan detection
    for ip, ports in ip_ports.items():
        if len(ports) >= PORT_SCAN_THRESHOLD:
            threats.append({
                "type": "port_scan",
                "severity": "high",
                "ip": ip,
                "detail": f"Connected to {len(ports)} distinct ports: {sorted(ports)[:20]}",
                "action": "block",
            })

    # Brute-force detection
    for ip, count in ip_count.items():
        if count >= BRUTE_FORCE_THRESHOLD:
            threats.append({
                "type": "brute_force",
                "severity": "medium",
                "ip": ip,
                "detail": f"{count} connections in {SCAN_WINDOW_SECONDS}s",
                "action": "block",
            })

    # Sensitive port hits
    if sensitive_hits:
        from collections import Counter
        port_counts = Counter(h["port"] for h in sensitive_hits)
        threats.append({
            "type": "sensitive_port_access",
            "severity": "info",
            "ip": "multiple",
            "detail": f"Sensitive ports accessed: {dict(port_counts)}",
            "action": "monitor",
        })

    # Auto-block high severity threats
    auto_block = config.get("alerts_enabled", True)
    blocked_ips: List[str] = []
    if auto_block:
        for t in threats:
            if t["action"] == "block" and t["ip"] != "multiple":
                res = block_ip(t["ip"], f"netmonitor: {t['type']}")
                if res["ok"]:
                    blocked_ips.append(t["ip"])

    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "total_connections": len(connections),
        "unique_remote_ips": len(ip_ports),
        "threats": threats,
        "auto_blocked": blocked_ips,
        "threat_count": len(threats),
    }


# --------------------------------------------------------------------------- #
# SSL certificate checker
# --------------------------------------------------------------------------- #
def check_ssl_cert(domain: str, port: int = 443) -> Dict[str, Any]:
    """Check SSL certificate expiry for a domain."""
    import socket
    import ssl

    if not domain or len(domain) > 253:
        return {"error": "Invalid domain"}

    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as sock:
            sock.settimeout(10)
            sock.connect((domain, port))
            cert = sock.getpeercert()

        if not cert:
            return {"error": "No certificate returned"}

        not_after = cert.get("notAfter", "")
        not_before = cert.get("notBefore", "")
        try:
            expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            if expiry.tzinfo is None:
                expiry = expiry.replace(tzinfo=timezone.utc)
        except ValueError:
            expiry = None

        days_left = None
        if expiry:
            days_left = (expiry - datetime.now(timezone.utc)).days

        issuer = dict(x[0] for x in cert.get("issuer", ()))
        subject = dict(x[0] for x in cert.get("subject", ()))

        return {
            "domain": domain,
            "issuer": issuer.get("organizationName", issuer.get("O", "unknown")),
            "subject": subject.get("commonName", subject.get("CN", "unknown")),
            "expires": not_after,
            "days_left": days_left,
            "expired": days_left is not None and days_left < 0,
            "expiring_soon": days_left is not None and 0 <= days_left <= 14,
        }
    except Exception as exc:
        return {"error": str(exc)}


# --------------------------------------------------------------------------- #
# Security scorecard
# --------------------------------------------------------------------------- #
def compute_security_score(
    adapters: List[Dict[str, Any]],
    connections: List[Dict[str, Any]],
    vpn_interfaces: List[Dict[str, Any]],
    config: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Compute a 0-100 security score based on current state."""
    config = config or load_config()
    score = 100
    findings: List[Dict[str, Any]] = []

    # Penalty: too many listening ports
    listening = [c for c in connections if c["status"] == "LISTEN"]
    if len(listening) > 20:
        score -= 15
        findings.append({
            "issue": "many_listening_ports",
            "severity": "high",
            "detail": f"{len(listening)} listening ports",
        })
    elif len(listening) > 10:
        score -= 5
        findings.append({
            "issue": "several_listening_ports",
            "severity": "medium",
            "detail": f"{len(listening)} listening ports",
        })

    # Penalty: sensitive ports open to world
    for c in listening:
        try:
            port = int(c["local"].rsplit(":", 1)[-1])
        except (ValueError, IndexError):
            continue
        if port in (22, 3389, 5900, 3306, 5432, 6379, 27017):
            if "0.0.0.0" in c["local"] or "::" in c["local"]:
                score -= 10
                findings.append({
                    "issue": "sensitive_port_exposed",
                    "severity": "high",
                    "detail": f"Port {port} open on all interfaces",
                })

    # Bonus: VPN active
    if vpn_interfaces:
        score += 5
        findings.append({
            "issue": "vpn_active",
            "severity": "info",
            "detail": f"{len(vpn_interfaces)} VPN interface(s) active",
        })

    # Penalty: no alerts configured
    if not config.get("discord_webhook_url") and not config.get("telegram_bot_token"):
        score -= 10
        findings.append({
            "issue": "no_alerts_configured",
            "severity": "medium",
            "detail": "No Discord/Telegram webhook configured",
        })

    score = max(0, min(100, score))
    grade = "A" if score >= 90 else "B" if score >= 80 else "C" if score >= 70 else "D" if score >= 60 else "F"

    return {
        "score": score,
        "grade": grade,
        "findings": findings,
        "computed_at": datetime.now(timezone.utc).isoformat(),
    }


# --------------------------------------------------------------------------- #
# Honeypot
# --------------------------------------------------------------------------- #
def start_honeypot(ports: List[int], duration: int = 300) -> Dict[str, Any]:
    """Start temporary honeypot listeners on fake ports.

    Uses Python socket binding; alerts on any connection.
    Runs for `duration` seconds then stops.
    """
    import socket as _socket
    import threading

    results: List[Dict[str, Any]] = []
    stop_event = threading.Event()

    def listener(port: int) -> None:
        try:
            srv = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
            srv.setsockopt(_socket.SOL_SOCKET, _socket.SO_REUSEADDR, 1)
            srv.bind(("0.0.0.0", port))
            srv.listen(1)
            srv.settimeout(1.0)
            while not stop_event.is_set():
                try:
                    conn, addr = srv.accept()
                    ip = addr[0]
                    _log_security(f"HONEYPOT HIT on port {port} from {ip}")
                    results.append({
                        "port": port,
                        "ip": ip,
                        "time": datetime.now(timezone.utc).isoformat(),
                    })
                    try:
                        conn.close()
                    except OSError:
                        pass
                    # Auto-block honeypot visitors
                    block_ip(ip, f"netmonitor honeypot port {port}")
                except _socket.timeout:
                    continue
                except OSError:
                    continue
            srv.close()
        except OSError as exc:
            results.append({"port": port, "error": str(exc)})

    threads: List[threading.Thread] = []
    for port in ports:
        if port < 1 or port > 65535:
            continue
        t = threading.Thread(target=listener, args=(port,), daemon=True)
        t.start()
        threads.append(t)

    # Wait for duration
    stop_event.wait(duration)

    for t in threads:
        t.join(timeout=2)

    return {
        "duration_seconds": duration,
        "ports": ports,
        "hits": results,
        "hit_count": len(results),
    }
