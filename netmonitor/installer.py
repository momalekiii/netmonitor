"""Interactive pre-install wizard for NetMonitor.

Asks the user which optional features to enable before installing.
Non-destructive: backs up existing config, never overwrites user files without consent.
"""

import json
import os
import shutil
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from .config import (
    BACKUPS_DIR, CONFIG_DIR, CONFIG_FILE_JSON, CONFIG_FILE_YAML, DEFAULT_CONFIG, LOGS_DIR,
)
from .features import FEATURE_REGISTRY, FeatureBase


class Installer:
    """Interactive installer with feature selection."""

    def __init__(self):
        self.config = dict(DEFAULT_CONFIG)
        self.selected_features: Dict[str, bool] = {}
        self.existing_config: Optional[Dict[str, Any]] = None
        self.backup_path: Optional[Path] = None

    # ------------------------------------------------------------------ #
    # Discovery
    # ------------------------------------------------------------------ #
    def detect_existing(self) -> bool:
        """Check if netmonitor is already installed/configured."""
        if CONFIG_FILE_JSON.exists():
            try:
                with CONFIG_FILE_JSON.open("r", encoding="utf-8") as fh:
                    self.existing_config = json.load(fh)
                return True
            except Exception:
                pass
        if CONFIG_FILE_YAML.exists():
            try:
                import yaml  # type: ignore
                with CONFIG_FILE_YAML.open("r", encoding="utf-8") as fh:
                    self.existing_config = yaml.safe_load(fh) or {}
                return True
            except Exception:
                pass
        return False

    def backup_existing(self) -> Optional[Path]:
        """Back up existing config before making changes."""
        if not self.existing_config:
            return None
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        BACKUPS_DIR.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_file = BACKUPS_DIR / f"config_backup_{stamp}.json"
        try:
            source = CONFIG_FILE_JSON if CONFIG_FILE_JSON.exists() else CONFIG_FILE_YAML
            if source and source.exists():
                shutil.copy2(source, backup_file)
                self.backup_path = backup_file
                return backup_file
        except Exception:
            pass
        return None

    # ------------------------------------------------------------------ #
    # Interactive prompts
    # ------------------------------------------------------------------ #
    def _ask_yes_no(self, question: str, default: bool = False) -> bool:
        suffix = " [Y/n]" if default else " [y/N]"
        while True:
            ans = input(question + suffix + " ").strip().lower()
            if not ans:
                return default
            if ans in ("y", "yes"):
                return True
            if ans in ("n", "no"):
                return False
            print("  Please answer y or n.")

    def _ask_text(self, question: str, default: str = "") -> str:
        if default:
            ans = input(question + " [" + default + "] ").strip()
            return ans if ans else default
        return input(question + " ").strip()

    def _ask_int(self, question: str, default: int, min_val: int = 1) -> int:
        while True:
            ans = input(question + " [" + str(default) + "] ").strip()
            if not ans:
                return default
            try:
                val = int(ans)
                if val < min_val:
                    print("  Must be at least " + str(min_val) + ".")
                    continue
                return val
            except ValueError:
                print("  Please enter a number.")

    def run(self) -> Dict[str, Any]:
        """Run the interactive installer."""
        print("=" * 60)
        print("  NetMonitor Interactive Installer")
        print("=" * 60)
        print()
        print("This installer will NOT overwrite your existing files.")
        print("Existing config will be backed up before any changes.")
        print()

        # Step 1: Detect existing installation
        if self.detect_existing():
            print("[!] Existing NetMonitor configuration detected.")
            if self.backup_existing():
                print("[+] Existing config backed up to: " + str(self.backup_path))
            print()
            # Merge existing config as defaults
            if isinstance(self.existing_config, dict):
                self.config.update(self.existing_config)
                # Preserve existing feature flags
                existing_features = self.existing_config.get("features", {})
                for fname in FEATURE_REGISTRY:
                    if fname in existing_features:
                        self.config.setdefault("features", {})[fname] = existing_features[fname]
        else:
            print("[i] No existing configuration found. Fresh install.")
            print()

        # Step 2: Feature selection
        print("Optional Features:")
        print("------------------")
        print("Choose which features to enable. Each adds capability")
        print("without modifying your existing system files.")
        print()

        for fname, fcls in sorted(FEATURE_REGISTRY.items()):
            feature = fcls(self.config)
            default = feature.default_enabled
            # If existing config had this feature, respect it
            if self.existing_config and isinstance(self.existing_config, dict):
                existing_feat = self.existing_config.get("features", {}).get(fname)
                if existing_feat is not None:
                    default = existing_feat

            prompt = "  Enable " + feature.name + "? (" + feature.description + ")"
            enabled = self._ask_yes_no(prompt, default=default)
            self.selected_features[fname] = enabled
            self.config.setdefault("features", {})[fname] = enabled
            print()

        # Step 3: Webhook configuration (if alerts enabled)
        print("Alerts & Webhooks:")
        print("------------------")
        if self._ask_yes_no("Configure Discord webhook?", default=False):
            url = self._ask_text("  Discord webhook URL", default=self.config.get("discord_webhook_url", ""))
            self.config["discord_webhook_url"] = url
        if self._ask_yes_no("Configure Telegram bot?", default=False):
            token = self._ask_text("  Telegram bot token", default=self.config.get("telegram_bot_token", ""))
            chat = self._ask_text("  Telegram chat ID", default=self.config.get("telegram_chat_id", ""))
            self.config["telegram_bot_token"] = token
            self.config["telegram_chat_id"] = chat
        print()

        # Step 4: Daemon / API
        print("Service Options:")
        print("----------------")
        self.config["interval"] = self._ask_int(
            "  Poll interval (seconds)", default=self.config.get("interval", 60), min_val=5
        )
        self.config["api_enabled"] = self._ask_yes_no(
            "  Enable HTTP API?", default=self.config.get("api_enabled", False)
        )
        if self.config["api_enabled"]:
            self.config["api_host"] = self._ask_text(
                "  API host", default=self.config.get("api_host", "127.0.0.1")
            )
            self.config["api_port"] = self._ask_int(
                "  API port", default=self.config.get("api_port", 8765), min_val=1024
            )
        print()

        # Step 5: Summary
        print("=" * 60)
        print("  Installation Summary")
        print("=" * 60)
        enabled_feats = [f for f, v in self.selected_features.items() if v]
        print("Features enabled: " + (", ".join(enabled_feats) if enabled_feats else "none"))
        print("Poll interval: " + str(self.config.get("interval", 60)) + "s")
        print("HTTP API: " + ("enabled on " + str(self.config.get("api_host", "")) + ":" + str(self.config.get("api_port", 8765)) if self.config.get("api_enabled") else "disabled"))
        print("Discord webhook: " + ("configured" if self.config.get("discord_webhook_url") else "not configured"))
        print("Telegram bot: " + ("configured" if self.config.get("telegram_bot_token") else "not configured"))
        print()
        if self.backup_path:
            print("Backup saved at: " + str(self.backup_path))
        print()

        confirm = self._ask_yes_no("Proceed with installation?", default=True)
        if not confirm:
            print("Installation cancelled.")
            return {"ok": False, "message": "Cancelled by user"}

        # Step 6: Save config
        self._save_config()

        # Step 7: Install each selected feature
        results = {}
        for fname, enabled in self.selected_features.items():
            if enabled:
                feature = FEATURE_REGISTRY[fname](self.config)
                res = feature.install()
                results[fname] = res

        print()
        print("=" * 60)
        print("  Installation Complete!")
        print("=" * 60)
        print("Run 'netmonitor' to start the interactive menu.")
        print("Run 'netmonitor daemon start' to run as a 24/7 background service.")
        print()

        return {"ok": True, "message": "Installed successfully", "features": results, "config": self.config}

    # ------------------------------------------------------------------ #
    # Persistence
    # ------------------------------------------------------------------ #
    def _save_config(self) -> None:
        """Save configuration to disk."""
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        LOGS_DIR.mkdir(parents=True, exist_ok=True)
        path = CONFIG_FILE_YAML if CONFIG_FILE_YAML.exists() else CONFIG_FILE_JSON
        try:
            import yaml  # type: ignore
            with path.open("w", encoding="utf-8") as fh:
                yaml.safe_dump(self.config, fh, default_flow_style=False, sort_keys=False)
        except ImportError:
            with CONFIG_FILE_JSON.open("w", encoding="utf-8") as fh:
                json.dump(self.config, fh, indent=2)
        except Exception:
            with CONFIG_FILE_JSON.open("w", encoding="utf-8") as fh:
                json.dump(self.config, fh, indent=2)


def main() -> int:
    installer = Installer()
    result = installer.run()
    if result["ok"]:
        print("[+] Installation finished successfully.")
        return 0
    print("[!] Installation was not completed.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
