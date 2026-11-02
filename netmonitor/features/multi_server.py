"""Multi-server monitoring feature.

Monitors remote servers via SSH. Reads server list from config.
Non-destructive: only reads via SSH, never writes to remote systems.
"""

from typing import Any, Dict

from ..config import DEFAULT_CONFIG


class MultiServerFeature:
    name = "multi_server"
    description = "Monitor remote servers via SSH"
    default_enabled = False
    requires_root = False

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.enabled = config.get("features", {}).get("multi_server", False)
        self.servers = config.get("remote_servers", [])

    def is_enabled(self) -> bool:
        return self.enabled

    def install(self) -> Dict[str, Any]:
        changes = []
        if self.enabled:
            changes.append(f"Multi-server monitoring configured for {len(self.servers)} server(s)")
            for srv in self.servers:
                changes.append(f"  - {srv.get('name', 'unnamed')} ({srv.get('host', '?')})")
        return {"ok": True, "message": "Multi-server feature configured", "changes": changes}

    def check_remote_servers(self) -> Dict[str, Any]:
        """Check all configured remote servers via SSH.

        Returns per-server status without modifying anything on remote.
        """
        results: Dict[str, Any] = {}
        try:
            import paramiko  # type: ignore
        except ImportError:
            return {"error": "paramiko not installed. Run: pip install paramiko"}

        for srv in self.servers:
            host = srv.get("host")
            port = srv.get("port", 22)
            user = srv.get("user", "root")
            name = srv.get("name", host or "unknown")
            key_file = srv.get("key_file", "")

            result: Dict[str, Any] = {"host": host, "port": port, "reachable": False}
            try:
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                connect_kwargs = {
                    "hostname": host,
                    "port": port,
                    "username": user,
                    "timeout": 10,
                }
                if key_file:
                    connect_kwargs["key_filename"] = key_file
                else:
                    connect_kwargs["password"] = srv.get("password", "")
                ssh.connect(**connect_kwargs)

                # Check if netmonitor is running on remote
                stdin, stdout, stderr = ssh.exec_command(
                    "netmonitor daemon status 2>/dev/null || echo 'not_installed'",
                    timeout=10,
                )
                output = stdout.read().decode().strip()
                result["reachable"] = True
                result["remote_status"] = output

                # Check listening ports on remote
                stdin, stdout, stderr = ssh.exec_command(
                    "ss -tlnp 2>/dev/null | head -20 || netstat -tlnp 2>/dev/null | head -20",
                    timeout=10,
                )
                result["listening"] = stdout.read().decode().strip()[:500]

                ssh.close()
            except Exception as exc:
                result["error"] = str(exc)[:200]

            results[name] = result

        return {"servers": results}
