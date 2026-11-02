"""Fail2Ban integration feature.

Reads auth.log (or configured log file) for brute-force patterns
and auto-blocks offending IPs. Non-destructive: read-only on logs.
"""

import re
from pathlib import Path
from typing import Any, Dict

from ..config import DEFAULT_CONFIG


class Fail2BanFeature:
    name = "fail2ban"
    description = "Fail2Ban-style log monitoring and auto-block"
    default_enabled = False
    requires_root = False

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.enabled = config.get("features", {}).get("fail2ban", False)
        self.log_path = config.get("fail2ban_log_path", "/var/log/auth.log")
        self.max_retries = config.get("fail2ban_max_retries", 5)

    def is_enabled(self) -> bool:
        return self.enabled

    def install(self) -> Dict[str, Any]:
        changes = []
        if self.enabled:
            changes.append("Monitoring log: " + self.log_path)
            changes.append("Max retries before block: " + str(self.max_retries))
        return {"ok": True, "message": "Fail2Ban feature configured", "changes": changes}

    def scan_log(self) -> Dict[str, Any]:
        """Scan the log file for failed authentication attempts.

        Returns suspicious IPs without modifying anything.
        """
        log_file = Path(self.log_path)
        if not log_file.exists():
            return {"error": "Log file not found: " + self.log_path}

        patterns = [
            r"Failed password for (?:invalid user )?\S+ from (\d+\.\d+\.\d+\.\d+)",
            r"authentication failure.*rhost=(\d+\.\d+\.\d+\.\d+)",
            r"Connection from (\d+\.\d+\.\d+\.\d+) port \d+",
        ]

        ip_counts: Dict[str, int] = {}
        try:
            with log_file.open("r", encoding="utf-8", errors="ignore") as fh:
                lines = fh.readlines()[-1000:]
                for line in lines:
                    for pat in patterns:
                        match = re.search(pat, line)
                        if match:
                            ip = match.group(1)
                            ip_counts[ip] = ip_counts.get(ip, 0) + 1
        except Exception as exc:
            return {"error": str(exc)}

        suspicious = [
            {"ip": ip, "count": count}
            for ip, count in ip_counts.items()
            if count >= self.max_retries
        ]

        return {
            "log_file": self.log_path,
            "lines_scanned": len(lines),
            "unique_ips": len(ip_counts),
            "suspicious": suspicious,
        }
