"""Optional feature modules for NetMonitor.

Each feature is a standalone module that can be enabled/disabled via config.
Features are non-destructive: they never overwrite existing user files.
"""

from typing import Any, Dict, Optional


class FeatureBase:
    """Base class for all optional features."""

    name: str = "base"
    description: str = ""
    default_enabled: bool = False
    requires_root: bool = False
    conflicts_with: list = []

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.enabled = config.get(f"feature_{self.name}", self.default_enabled)

    def is_enabled(self) -> bool:
        return self.enabled

    def install(self) -> Dict[str, Any]:
        """Install/configure the feature. Returns {ok, message, changes}."""
        return {"ok": True, "message": f"{self.name} installed", "changes": []}

    def uninstall(self) -> Dict[str, Any]:
        """Remove the feature configuration."""
        return {"ok": True, "message": f"{self.name} removed", "changes": []}

    def status(self) -> Dict[str, Any]:
        """Return current feature status."""
        return {
            "name": self.name,
            "enabled": self.enabled,
            "description": self.description,
        }


# Feature registry: name -> FeatureBase subclass
FEATURE_REGISTRY: Dict[str, type] = {}


def register_feature(cls: type) -> type:
    """Decorator to register a feature class."""
    FEATURE_REGISTRY[cls.name] = cls
    return cls


# Auto-register all feature modules
from . import (  # noqa: E402
    auto_remediation,
    bandwidth_anomaly,
    dns_leak,
    fail2ban,
    ja3_fingerprinting,
    multi_server,
    prometheus,
    scheduled_reports,
    ssl_transparency,
    telegram_bot,
    uptime_monitor,
)

for _mod in (
    auto_remediation,
    bandwidth_anomaly,
    dns_leak,
    fail2ban,
    ja3_fingerprinting,
    multi_server,
    prometheus,
    scheduled_reports,
    ssl_transparency,
    telegram_bot,
    uptime_monitor,
):
    for _attr in dir(_mod):
        _obj = getattr(_mod, _attr)
        # Duck typing: feature classes have name, description, default_enabled, requires_root, is_enabled, install
        if (
            isinstance(_obj, type)
            and _obj is not FeatureBase
            and hasattr(_obj, "name")
            and hasattr(_obj, "description")
            and hasattr(_obj, "default_enabled")
            and hasattr(_obj, "requires_root")
            and hasattr(_obj, "is_enabled")
            and hasattr(_obj, "install")
        ):
            register_feature(_obj)


def get_available_features() -> Dict[str, type]:
    """Return all registered features."""
    return dict(FEATURE_REGISTRY)


def load_feature(name: str, config: Dict[str, Any]) -> Optional[FeatureBase]:
    """Instantiate a feature by name."""
    cls = FEATURE_REGISTRY.get(name)
    if cls is None:
        return None
    return cls(config)
