"""Uptime monitoring feature.

Pings external endpoints and alerts when they go down.
Non-destructive: only sends outgoing ICMP/HTTP probes.
"""

import socket
import time
from typing import Any, Dict

from ..config import DEFAULT_CONFIG


class UptimeMonitorFeature:
    name = "uptime_monitor"
    description = "Monitor external endpoints for uptime"
    default_enabled = False
    requires_root = False

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.enabled = config.get("features", {}).get("uptime_monitor", False)
        self.targets = config.get("uptime_targets", [])

    def is_enabled(self) -> bool:
        return self.enabled

    def install(self) -> Dict[str, Any]:
        changes = []
        if self.enabled:
            changes.append("Monitoring " + str(len(self.targets)) + " endpoint(s)")
            for t in self.targets:
                changes.append("  - " + str(t.get("name", "unnamed")) + " (" + str(t.get("host", "?")) + ")")
        return {"ok": True, "message": "Uptime monitor configured", "changes": changes}

    def check_targets(self) -> Dict[str, Any]:
        """Check all configured targets.

        Returns per-target reachability without modifying anything.
        """
        results: Dict[str, Any] = {}
        for tgt in self.targets:
            host = tgt.get("host")
            port = tgt.get("port", 443)
            name = tgt.get("name", host or "unknown")
            timeout = tgt.get("timeout", 5)

            result: Dict[str, Any] = {"host": host, "port": port, "reachable": False}
            try:
                start = time.time()
                sock = socket.create_connection((host, port), timeout=timeout)
                latency = (time.time() - start) * 1000
                sock.close()
                result["reachable"] = True
                result["latency_ms"] = round(latency, 1)
            except Exception as exc:
                result["error"] = str(exc)[:200]

            results[name] = result

        return {"targets": results}
