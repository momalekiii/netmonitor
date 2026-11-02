"""Auto-remediation feature.

Automatically restarts services when anomalies are detected.
Non-destructive: only restarts systemd services that the user configures.
"""

import subprocess
from typing import Any, Dict

from ..config import DEFAULT_CONFIG


class AutoRemediationFeature:
    name = "auto_remediation"
    description = "Auto-restart tunnel/daemon when anomalies detected"
    default_enabled = False
    requires_root = True

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.enabled = config.get("features", {}).get("auto_remediation", False)
        self.services = config.get("remediation_services", ["netmonitor"])
        self.max_restarts = config.get("remediation_max_restarts", 3)

    def is_enabled(self) -> bool:
        return self.enabled

    def install(self) -> Dict[str, Any]:
        changes = []
        if self.enabled:
            changes.append(f"Auto-remediation enabled for services: {', '.join(self.services)}")
            changes.append(f"Max restarts per incident: {self.max_restarts}")
        return {"ok": True, "message": "Auto-remediation configured", "changes": changes}

    def remediate(self, anomaly_type: str, detail: str = "") -> Dict[str, Any]:
        """Attempt to remediate an anomaly.

        Only restarts services if auto-remediation is enabled.
        """
        if not self.enabled:
            return {"ok": False, "message": "Auto-remediation not enabled"}

        results: Dict[str, Any] = {"actions": []}
        for svc in self.services:
            try:
                # Check if service is active
                check = subprocess.run(
                    ["systemctl", "is-active", "--quiet", svc],
                    capture_output=True,
                    timeout=10,
                )
                if check.returncode != 0:
                    # Service is down, try to restart
                    restart = subprocess.run(
                        ["systemctl", "restart", svc],
                        capture_output=True,
                        text=True,
                        timeout=15,
                    )
                    results["actions"].append({
                        "service": svc,
                        "action": "restart",
                        "success": restart.returncode == 0,
                        "output": restart.stdout.strip()[:200],
                        "error": restart.stderr.strip()[:200],
                    })
            except FileNotFoundError:
                results["actions"].append({
                    "service": svc,
                    "action": "skipped",
                    "reason": "systemctl not available",
                })
            except Exception as exc:
                results["actions"].append({
                    "service": svc,
                    "action": "error",
                    "error": str(exc)[:200],
                })

        return {"ok": True, "anomaly": anomaly_type, "actions": results["actions"]}
