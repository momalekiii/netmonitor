"""Scheduled reports feature.

Generates and sends periodic reports via webhook.
Non-destructive: only sends outgoing messages.
"""

import json
from datetime import datetime
from typing import Any, Dict

from ..config import DEFAULT_CONFIG


class ScheduledReportsFeature:
    name = "scheduled_reports"
    description = "Daily/weekly reports via webhook"
    default_enabled = False
    requires_root = False

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.enabled = config.get("features", {}).get("scheduled_reports", False)
        self.schedule = config.get("report_schedule", "disabled")
        self.webhook_url = config.get("report_webhook_url", "")

    def is_enabled(self) -> bool:
        return self.enabled

    def install(self) -> Dict[str, Any]:
        changes = []
        if self.enabled:
            changes.append(f"Report schedule: {self.schedule}")
            if self.webhook_url:
                changes.append(f"Report webhook: {self.webhook_url[:30]}...")
            else:
                changes.append("WARNING: No report webhook URL configured")
        return {"ok": True, "message": "Scheduled reports configured", "changes": changes}

    def generate_report(self) -> Dict[str, Any]:
        """Generate a security/status report."""
        try:
            from ..network import get_connections, listening_ports, get_adapters, detect_vpn
            from ..security import compute_security_score, list_blocked
            from ..config import load_config

            cfg = load_config()
            conns = get_connections()
            adapters = get_adapters()
            vpns = detect_vpn()
            blocked = list_blocked()

            score_result = compute_security_score(adapters, conns, vpns, cfg)

            report = {
                "generated_at": datetime.now().isoformat(),
                "connections": len(conns),
                "listening_ports": len(listening_ports()),
                "adapters": len(adapters),
                "vpn_interfaces": len(vpns),
                "blocked_ips": len(blocked.get("blocked", {})),
                "security_score": score_result.get("score", 0),
                "security_grade": score_result.get("grade", "F"),
            }
            return report
        except Exception as exc:
            return {"error": str(exc)}

    def send_report(self) -> Dict[str, Any]:
        """Send report via configured webhook."""
        if not self.webhook_url:
            return {"ok": False, "error": "No report webhook URL configured"}

        report = self.generate_report()
        if "error" in report:
            return report

        try:
            import requests
            message = (
                f"📊 NetMonitor Report ({report['generated_at'][:10]})\n"
                f"Connections: {report['connections']}\n"
                f"Listening ports: {report['listening_ports']}\n"
                f"VPN interfaces: {report['vpn_interfaces']}\n"
                f"Blocked IPs: {report['blocked_ips']}\n"
                f"Security score: {report['security_score']}/100 ({report['security_grade']})"
            )
            resp = requests.post(self.webhook_url, json={"content": message}, timeout=10)
            return {"ok": resp.status_code in (200, 204), "status": resp.status_code}
        except Exception as exc:
            return {"ok": False, "error": str(exc)}
