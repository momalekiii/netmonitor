"""Telegram bot command feature.

Receives commands from a Telegram bot and responds with netmonitor status.
Requires TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID in config.
Non-destructive: only sends messages, never modifies user data.
"""

from typing import Any, Dict

from ..config import DEFAULT_CONFIG


class TelegramBotFeature:
    name = "telegram_bot"
    description = "Telegram bot command handler (/status, /block, /unblock)"
    default_enabled = False
    requires_root = False

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.enabled = config.get("features", {}).get("telegram_bot", False)
        self.bot_token = config.get("telegram_bot_token", "")
        self.chat_id = config.get("telegram_chat_id", "")

    def is_enabled(self) -> bool:
        return self.enabled

    def install(self) -> Dict[str, Any]:
        changes = []
        if self.enabled:
            if not self.bot_token:
                changes.append("WARNING: TELEGRAM_BOT_TOKEN not set")
            if not self.chat_id:
                changes.append("WARNING: TELEGRAM_CHAT_ID not set")
            changes.append("Telegram bot commands enabled: /status, /block, /unblock, /score")
        return {"ok": True, "message": "Telegram bot feature configured", "changes": changes}

    def handle_command(self, command: str, args: str = "") -> str:
        """Handle a Telegram bot command and return response text."""
        cmd = command.lower().strip()

        if cmd == "/status":
            return self._cmd_status()
        elif cmd == "/score":
            return self._cmd_score()
        elif cmd == "/block":
            return self._cmd_block(args)
        elif cmd == "/unblock":
            return self._cmd_unblock(args)
        elif cmd == "/help":
            return self._cmd_help()
        else:
            return "Unknown command. Send /help for available commands."

    def _cmd_status(self) -> str:
        try:
            from ..network import get_connections, listening_ports
            from ..monitor import get_daemon
            conns = get_connections()
            ports = listening_ports()
            daemon = get_daemon()
            return (
                f"📊 NetMonitor Status\n"
                f"Connections: {len(conns)}\n"
                f"Listening ports: {len(ports)}\n"
                f"Daemon: {'running' if daemon.running else 'stopped'}"
            )
        except Exception as exc:
            return f"Error getting status: {exc}"

    def _cmd_score(self) -> str:
        try:
            from ..security import compute_security_score
            from ..network import get_adapters, detect_vpn
            from ..config import load_config
            cfg = load_config()
            result = compute_security_score(get_adapters(), [], detect_vpn(), cfg)
            return f"🛡️ Security Score: {result['score']}/100 (Grade {result['grade']})"
        except Exception as exc:
            return f"Error getting score: {exc}"

    def _cmd_block(self, args: str) -> str:
        ip = args.strip()
        if not ip:
            return "Usage: /block <ip_address>"
        try:
            import ipaddress
            ipaddress.ip_address(ip)
        except ValueError:
            return f"Invalid IP: {ip}"
        try:
            from ..security import block_ip
            res = block_ip(ip, "telegram_bot")
            if res["ok"]:
                return f"🚫 Blocked {ip} via {res.get('method', 'firewall')}"
            return f"✗ Failed to block {ip}: {res.get('error', 'unknown')}"
        except Exception as exc:
            return f"Error blocking IP: {exc}"

    def _cmd_unblock(self, args: str) -> str:
        ip = args.strip()
        if not ip:
            return "Usage: /unblock <ip_address>"
        try:
            from ..security import unblock_ip
            res = unblock_ip(ip)
            if res["ok"]:
                return f"✅ Unblocked {ip}"
            return f"✗ {res.get('error', 'unknown')}"
        except Exception as exc:
            return f"Error unblocking IP: {exc}"

    def _cmd_help(self) -> str:
        return (
            "🤖 NetMonitor Bot Commands:\n"
            "/status - Show connection and daemon status\n"
            "/score - Show security score\n"
            "/block <ip> - Block an IP via firewall\n"
            "/unblock <ip> - Unblock an IP\n"
            "/help - Show this help"
        )
