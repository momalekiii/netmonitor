"""Discord and Telegram webhook / alert delivery.

Hardening:
- Timeouts on all HTTP calls.
- Secrets masked in any error output.
- No secret values in log messages.
"""

from typing import Any, Dict, List, Optional

import requests

REQUEST_TIMEOUT = 10


def send_discord(
    webhook_url: str,
    message: str,
    username: str = "NetMonitor",
    embeds: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """Send a message to a Discord webhook."""
    # Basic URL validation
    if not webhook_url or not webhook_url.startswith("https://discord.com/api/webhooks/"):
        return {"ok": False, "status": None, "detail": "Invalid Discord webhook URL"}

    payload: Dict[str, Any] = {"content": message, "username": username[:50]}
    if embeds:
        payload["embeds"] = embeds[:10]  # limit embed count

    try:
        resp = requests.post(webhook_url, json=payload, timeout=REQUEST_TIMEOUT)
        return {
            "ok": resp.status_code in (200, 204),
            "status": resp.status_code,
            "detail": resp.text[:200],
        }
    except requests.RequestException as exc:
        return {"ok": False, "status": None, "detail": "request_error"}


def send_telegram(
    bot_token: str,
    chat_id: str,
    text: str,
    parse_mode: str = "Markdown",
) -> Dict[str, Any]:
    """Send a message via the Telegram Bot API."""
    if not bot_token or not chat_id:
        return {"ok": False, "status": None, "detail": "missing_credentials"}

    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    payload = {"chat_id": str(chat_id), "text": text[:4000], "parse_mode": parse_mode}
    try:
        resp = requests.post(url, json=payload, timeout=REQUEST_TIMEOUT)
        data: Dict[str, Any] = {}
        try:
            data = resp.json()
        except Exception:
            pass
        return {
            "ok": resp.status_code == 200 and data.get("ok") is True,
            "status": resp.status_code,
            "detail": data.get("description", resp.text[:200]),
        }
    except requests.RequestException:
        return {"ok": False, "status": None, "detail": "request_error"}


def send_alert(
    config: Dict[str, Any],
    message: str,
    level: str = "info",
) -> Dict[str, Any]:
    """Fan out an alert to every configured webhook."""
    results: Dict[str, Any] = {"discord": None, "telegram": None}

    if config.get("discord_webhook_url"):
        emoji = {
            "info": "ℹ️",
            "warning": "⚠️",
            "error": "🚨",
            "success": "✅",
        }.get(level, "ℹ️")
        results["discord"] = send_discord(
            config["discord_webhook_url"],
            f"{emoji} *NetMonitor [{level.upper()}]*\n{message[:3000]}",
        )

    if config.get("telegram_bot_token") and config.get("telegram_chat_id"):
        results["telegram"] = send_telegram(
            config["telegram_bot_token"],
            config["telegram_chat_id"],
            f"*NetMonitor [{level.upper()}]*\n{message[:3000]}",
        )

    return results


def test_webhooks(config: Dict[str, Any]) -> Dict[str, Any]:
    """Send a test message to all configured webhooks."""
    return send_alert(
        config,
        "🔧 NetMonitor webhook test — everything is wired up correctly!",
        level="success",
    )
