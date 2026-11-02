"""Network inspection: sockets, ports, adapters, VPN detection.

Hardening:
- All psutil calls wrapped in try/except to avoid daemon crashes.
- Port parsing is defensive; malformed entries are skipped.
- No shell execution; no subprocess; pure Python introspection.
"""

from typing import Any, Dict, List, Optional

import psutil


# Interface name prefixes commonly used by VPN / tunnel interfaces.
VPN_PREFIXES = (
    "tun", "tap", "wg", "ppp", "ipsec", "utun", "virbr", "docker",
    "vmnet", "veth", "br-", "zstunnel", "headerscale", "tailscale",
    "wg0", "wg1", "utun", "ipsec0", "ppp0",
)


def _safe_call(func, *args, **kwargs) -> Any:
    """Call a psutil function safely, returning a safe default on error."""
    try:
        return func(*args, **kwargs)
    except (psutil.AccessDenied, NotImplementedError, OSError, Exception):
        return None


def get_connections(kind: str = "inet") -> List[Dict[str, Any]]:
    """Return a list of network connections/sockets.

    Each dict contains: local, remote, status, type, family, pid, process.
    Malformed entries are skipped rather than raising.
    """
    conns: List[Dict[str, Any]] = []
    raw = _safe_call(psutil.net_connections, kind=None if kind == "all" else kind)
    if not raw:
        return conns

    for c in raw:
        try:
            laddr = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "N/A"
            raddr = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "N/A"
        except AttributeError:
            laddr = raddr = "N/A"

        pid = c.pid if c.pid else -1
        process = "N/A"
        if pid and pid > 0:
            try:
                p = psutil.Process(pid)
                process = p.name()
            except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
                process = "unknown"

        conns.append(
            {
                "local": laddr,
                "remote": raddr,
                "status": c.status or "N/A",
                "type": str(c.type).replace("SocketKind.", ""),
                "family": str(c.family).replace("AddressFamily.", ""),
                "pid": pid,
                "process": process,
            }
        )
    return conns


def listening_ports() -> List[Dict[str, Any]]:
    """Return only listening (server) sockets."""
    return [c for c in get_connections() if c["status"] == "LISTEN"]


def established_connections() -> List[Dict[str, Any]]:
    """Return only established connections."""
    return [c for c in get_connections() if c["status"] == "ESTABLISHED"]


def _parse_local_port(local: str) -> Optional[int]:
    """Extract the port number from a local address string like '0.0.0.0:8080'."""
    try:
        if ":" in local:
            return int(local.rsplit(":", 1)[-1])
    except (ValueError, IndexError):
        pass
    return None


def check_port(port: int) -> Optional[Dict[str, Any]]:
    """Check whether a specific TCP port is in use."""
    if port < 1 or port > 65535:
        return None
    for c in get_connections(kind="inet"):
        local_port = _parse_local_port(c["local"])
        if local_port == port:
            return c
    return None


def get_adapters() -> List[Dict[str, Any]]:
    """Return network adapter / interface details."""
    addrs = _safe_call(psutil.net_if_addrs) or {}
    stats = _safe_call(psutil.net_if_stats) or {}
    counters = _safe_call(psutil.net_io_counters, pernic=True) or {}

    adapters: List[Dict[str, Any]] = []
    for iface, addr_list in addrs.items():
        try:
            stat = stats.get(iface)
            is_up = stat.isup if stat else False
            speed = stat.speed if stat else 0
            mtu = stat.mtu if stat else 0
            duplex = str(stat.duplex) if stat else "N/A"
        except AttributeError:
            is_up, speed, mtu, duplex = False, 0, 0, "N/A"

        ip_list: List[str] = []
        mac_list: List[str] = []
        for snic in addr_list or []:
            fam = str(snic.family)
            if "AF_INET" in fam:
                ip_list.append(f"{snic.address}/{snic.netmask or 'N/A'}")
            elif "AF_INET6" in fam:
                ip_list.append(f"{snic.address} (v6)")
            elif "AF_LINK" in fam or "AF_PACKET" in fam:
                mac_list.append(snic.address)

        io = counters.get(iface)
        adapters.append(
            {
                "name": iface,
                "status": "up" if is_up else "down",
                "speed_mbps": speed,
                "mtu": mtu,
                "duplex": duplex.replace("NicDuplex.", ""),
                "ips": ip_list,
                "macs": mac_list,
                "bytes_sent": io.bytes_sent if io else 0,
                "bytes_recv": io.bytes_recv if io else 0,
                "packets_sent": io.packets_sent if io else 0,
                "packets_recv": io.packets_recv if io else 0,
                "is_vpn": any(
                    iface.lower().startswith(p) for p in VPN_PREFIXES
                ),
            }
        )
    return adapters


def detect_vpn() -> List[Dict[str, Any]]:
    """Return adapters that look like VPN / tunnel interfaces."""
    return [a for a in get_adapters() if a["is_vpn"]]


def active_vpn_summary() -> str:
    """Human-readable summary of active VPN interfaces."""
    vpns = detect_vpn()
    if not vpns:
        return "No VPN/tunnel interfaces detected."
    lines = [f"Active VPN/tunnel interfaces: {len(vpns)}"]
    for v in vpns:
        ips = ", ".join(v["ips"]) if v["ips"] else "no IP"
        lines.append(
            f"  • {v['name']} — {v['status']}, IPs: {ips}, "
            f"speed: {v['speed_mbps']} Mbps"
        )
    return "\n".join(lines)
