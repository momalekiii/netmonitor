"""Configuration management for netmonitor — JSON + YAML support.

Security notes:
- Secrets (webhook URLs, bot tokens) are stored on disk at ~/.netmonitor.
  File permissions are restricted to owner-only (0o600) where possible.
- No secrets are ever logged or echoed to stdout.
"""

import json
import os
import re
from pathlib import Path
from typing import Any, Dict, Optional

try:
    import yaml  # type: ignore
    HAS_YAML = True
except ImportError:  # pragma: no cover
    HAS_YAML = False

CONFIG_DIR = Path.home() / ".netmonitor"
CONFIG_FILE_JSON = CONFIG_DIR / "config.json"
CONFIG_FILE_YAML = CONFIG_DIR / "config.yaml"
LOGS_DIR = CONFIG_DIR / "logs"
HISTORY_DIR = CONFIG_DIR / "history"
BACKUPS_DIR = CONFIG_DIR / "backups"
STATE_FILE = CONFIG_DIR / "state.json"

# Regex for validating webhook URLs (Discord/Telegram)
WEBHOOK_URL_RE = re.compile(r"^https://discord\.com/api/webhooks/\d+/[\w-]+$")
TELEGRAM_TOKEN_RE = re.compile(r"^\d+:[A-Za-z0-9_-]{35,}$")


DEFAULT_CONFIG: Dict[str, Any] = {
    "version": 1,
    "interval": 60,
    "theme": "dark",
    "alerts_enabled": True,
    "log_rotation": True,
    "max_log_files": 10,
    "max_history_files": 500,
    "api_enabled": False,
    "api_host": "127.0.0.1",
    "api_port": 8765,
    "api_rate_limit": 60,  # requests per minute per IP
    "discord_webhook_url": os.getenv("DISCORD_WEBHOOK_URL", ""),
    "telegram_bot_token": os.getenv("TELEGRAM_BOT_TOKEN", ""),
    "telegram_chat_id": os.getenv("TELEGRAM_CHAT_ID", ""),
    "geoip_provider": "ipapi",
    "geoip_rate_limit": 1,  # requests per second
    "export_format": "json",
    "watch_ports": [],
    "alert_rules": {
        "port_down": True,
        "port_up": True,
        "new_connection": True,
        "geo_anomaly": True,
        "geo_anomaly_countries": [],
        "known_countries": [],
    },
    # --- Optional feature flags ---
    "features": {
        "prometheus": False,
        "multi_server": False,
        "telegram_bot": False,
        "auto_remediation": False,
        "scheduled_reports": False,
        "fail2ban": False,
        "uptime_monitor": False,
        "dns_leak": False,
        "bandwidth_anomaly": False,
        "ssl_transparency": False,
        "ja3_fingerprinting": False,
    },
    # --- Multi-server targets ---
    "remote_servers": [],
    # --- Uptime monitoring targets ---
    "uptime_targets": [],
    # --- Scheduled reports ---
    "report_schedule": "daily",  # daily, weekly, disabled
    "report_webhook_url": "",
    # --- Fail2Ban ---
    "fail2ban_log_path": "/var/log/auth.log",
    # --- Bandwidth anomaly ---
    "bandwidth_baseline_mb": 0,
    "bandwidth_anomaly_threshold": 3.0,  # 3x baseline
}


def _config_path() -> Path:
    if HAS_YAML and CONFIG_FILE_YAML.exists():
        return CONFIG_FILE_YAML
    return CONFIG_FILE_JSON


def ensure_dirs() -> None:
    """Create runtime directories with restricted permissions."""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    HISTORY_DIR.mkdir(parents=True, exist_ok=True)
    BACKUPS_DIR.mkdir(parents=True, exist_ok=True)
    # Restrict config dir to owner only
    try:
        os.chmod(CONFIG_DIR, 0o700)
    except OSError:
        pass


def _restrict_file(path: Path) -> None:
    """Chmod 0o600 on a file if it exists."""
    try:
        if path.exists():
            os.chmod(path, 0o600)
    except OSError:
        pass


def load_config() -> Dict[str, Any]:
    """Load configuration from disk, falling back to defaults."""
    ensure_dirs()
    config = dict(DEFAULT_CONFIG)
    path = _config_path()
    if not path.exists():
        return config
    try:
        if path.suffix == ".yaml" and HAS_YAML:
            import yaml  # type: ignore
            with path.open("r", encoding="utf-8") as fh:
                user_cfg = yaml.safe_load(fh) or {}
        else:
            with path.open("r", encoding="utf-8") as fh:
                user_cfg = json.load(fh) or {}
        if isinstance(user_cfg, dict):
            config.update(user_cfg)
            if "alert_rules" in user_cfg and isinstance(user_cfg["alert_rules"], dict):
                config["alert_rules"].update(user_cfg["alert_rules"])
    except (json.JSONDecodeError, OSError, ImportError, yaml.YAMLError if HAS_YAML else Exception):
        pass
    # Clamp interval to sane bounds
    try:
        config["interval"] = max(5, min(int(config.get("interval", 60)), 86400))
    except (ValueError, TypeError):
        config["interval"] = 60
    try:
        config["api_port"] = max(1024, min(int(config.get("api_port", 8765)), 65535))
    except (ValueError, TypeError):
        config["api_port"] = 8765
    return config


def save_config(config: Dict[str, Any]) -> None:
    """Persist configuration to disk with owner-only permissions."""
    ensure_dirs()
    path = CONFIG_FILE_YAML if HAS_YAML else CONFIG_FILE_JSON
    try:
        if path.suffix == ".yaml":
            import yaml  # type: ignore
            with path.open("w", encoding="utf-8") as fh:
                yaml.safe_dump(config, fh, default_flow_style=False, sort_keys=False)
        else:
            with path.open("w", encoding="utf-8") as fh:
                json.dump(config, fh, indent=2)
    except ImportError:
        with CONFIG_FILE_JSON.open("w", encoding="utf-8") as fh:
            json.dump(config, fh, indent=2)
    _restrict_file(path)


def get_state() -> Optional[Dict[str, Any]]:
    """Load the last monitoring state (for change detection)."""
    if not STATE_FILE.exists():
        return None
    try:
        with STATE_FILE.open("r", encoding="utf-8") as fh:
            return json.load(fh)
    except (json.JSONDecodeError, OSError):
        return None


def save_state(state: Dict[str, Any]) -> None:
    """Persist monitoring state for change detection."""
    ensure_dirs()
    with STATE_FILE.open("w", encoding="utf-8") as fh:
        json.dump(state, fh, indent=2, default=str)
    _restrict_file(STATE_FILE)


def mask_secret(value: str) -> str:
    """Return a masked version of a secret for safe display/logging."""
    if not value:
        return ""
    if len(value) <= 8:
        return "*" * len(value)
    return value[:4] + "*" * (len(value) - 8) + value[-4:]


def validate_webhook_url(url: str) -> bool:
    """Basic validation for Discord webhook URLs."""
    return bool(url and WEBHOOK_URL_RE.match(url))


def validate_telegram_token(token: str) -> bool:
    """Basic validation for Telegram bot tokens."""
    return bool(token and TELEGRAM_TOKEN_RE.match(token))
