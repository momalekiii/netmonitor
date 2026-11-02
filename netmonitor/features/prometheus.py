"""Prometheus metrics endpoint for NetMonitor.

Exposes /metrics on a configurable port for scraping by Prometheus.
Non-destructive: binds to a separate port, never overwrites existing services.
"""

from typing import Any, Dict

from ..config import DEFAULT_CONFIG


class PrometheusFeature:
    name = "prometheus"
    description = "Prometheus metrics endpoint (/metrics) for scraping"
    default_enabled = False
    requires_root = False

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.enabled = config.get("features", {}).get("prometheus", False)
        self.port = config.get("prometheus_port", 9091)

    def is_enabled(self) -> bool:
        return self.enabled

    def install(self) -> Dict[str, Any]:
        changes = []
        if self.enabled:
            changes.append(f"Prometheus metrics will be exposed on port {self.port}")
        return {"ok": True, "message": "Prometheus feature configured", "changes": changes}

    def get_metrics_text(self) -> str:
        """Generate Prometheus-formatted metrics text."""
        lines = [
            "# HELP netmonitor_connections_total Total active network connections",
            "# TYPE netmonitor_connections_total gauge",
            f'netmonitor_connections_total{{kind="inet"}} {self._count_connections()}',
            "",
            "# HELP netmonitor_listening_ports Total listening ports",
            "# TYPE netmonitor_listening_ports gauge",
            f"netmonitor_listening_ports {self._count_listening()}",
            "",
            "# HELP netmonitor_security_score Current security score (0-100)",
            "# TYPE netmonitor_security_score gauge",
            f"netmonitor_security_score {self._security_score()}",
            "",
            "# HELP netmonitor_blocked_ips Number of blocked IPs",
            "# TYPE netmonitor_blocked_ips gauge",
            f"netmonitor_blocked_ips {self._blocked_count()}",
            "",
            "# HELP netmonitor_daemon_running Whether the daemon is running",
            "# TYPE netmonitor_daemon_running gauge",
            f"netmonitor_daemon_running {1 if self._daemon_running() else 0}",
        ]
        return "\n".join(lines) + "\n"

    # --- Internal helpers (safe, read-only) ---
    def _count_connections(self) -> int:
        try:
            from ..network import get_connections
            return len(get_connections())
        except Exception:
            return 0

    def _count_listening(self) -> int:
        try:
            from ..network import listening_ports
            return len(listening_ports())
        except Exception:
            return 0

    def _security_score(self) -> int:
        try:
            from ..security import compute_security_score
            from ..network import get_adapters, detect_vpn
            from ..config import load_config
            cfg = load_config()
            result = compute_security_score(get_adapters(), [], detect_vpn(), cfg)
            return result.get("score", 0)
        except Exception:
            return 0

    def _blocked_count(self) -> int:
        try:
            from ..security import list_blocked
            return len(list_blocked().get("blocked", {}))
        except Exception:
            return 0

    def _daemon_running(self) -> bool:
        try:
            from ..monitor import get_daemon
            return get_daemon().running
        except Exception:
            return False
