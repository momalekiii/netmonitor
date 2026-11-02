"""Background monitoring daemon with change detection, geo anomaly & port alerts.

Hardening:
- Thread-safe state access via Lock.
- GeoIP lookups are rate-limited and capped to avoid API abuse.
- All exceptions caught per-tick so the daemon never dies.
- No secrets in logs or state files.
- State snapshots rotated to prevent disk exhaustion.
"""

import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from .config import (
    BACKUPS_DIR, HISTORY_DIR, LOGS_DIR, STATE_FILE, load_config, save_state, get_state,
)
from .network import get_connections, listening_ports, detect_vpn, get_adapters
from .intel import geoip_lookup
from .webhooks import send_alert


class NetMonitorDaemon:
    """24/7 background monitor. Polls network state, detects changes, sends alerts."""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or load_config()
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()
        self._state = get_state() or {
            "last_connections": [],
            "last_ports": [],
            "last_countries": [],
            "last_adapters": [],
            "first_seen": datetime.now().isoformat(),
            "geoip_last_call": 0.0,
        }
        self._running = False
        self._geoip_lock = threading.Lock()
        self._last_geoip_call = 0.0

    # ------------------------------------------------------------------ #
    # Lifecycle
    # ------------------------------------------------------------------ #
    def start(self) -> None:
        if self._running:
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True, name="netmonitor-daemon")
        self._thread.start()
        self._running = True

    def stop(self, timeout: float = 5.0) -> None:
        self._stop.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=timeout)
        self._running = False

    @property
    def running(self) -> bool:
        return self._running and (self._thread is not None and self._thread.is_alive())

    # ------------------------------------------------------------------ #
    # Main loop
    # ------------------------------------------------------------------ #
    def _loop(self) -> None:
        interval = int(self.config.get("interval", 60))
        while not self._stop.wait(interval):
            try:
                self._tick()
            except Exception as exc:  # keep daemon alive on unexpected errors
                self._log_error(f"Monitor tick failed: {exc}")

    def _tick(self) -> None:
        now = datetime.now().isoformat()
        config = self.config

        # Gather current state
        connections = get_connections()
        ports = listening_ports()
        adapters = get_adapters()
        vpns = detect_vpn()

        # Geo enrichment on established remote IPs (rate-limited, capped)
        remote_ips = self._extract_remote_ips(connections)
        countries = self._lookup_countries_limited(remote_ips, config)

        # Change detection against last state
        alerts: List[str] = []
        rules = config.get("alert_rules", {})

        prev_ports = self._state.get("last_ports", [])
        curr_ports = [p["local"] for p in ports]
        if rules.get("port_down", True):
            for p in prev_ports:
                if p not in curr_ports:
                    alerts.append(f"🔴 PORT DOWN: {p} is no longer listening")
        if rules.get("port_up", True):
            for p in curr_ports:
                if p not in prev_ports:
                    alerts.append(f"🟢 PORT UP: {p} is now listening")

        prev_countries = set(self._state.get("last_countries", []))
        curr_countries = set(countries.values())
        new_countries = curr_countries - prev_countries
        if rules.get("geo_anomaly", True) and new_countries:
            known = set(config.get("alert_rules", {}).get("known_countries", []))
            specified = set(config.get("alert_rules", {}).get("geo_anomaly_countries", []))
            for c in sorted(new_countries):
                if known and c in known:
                    continue
                if specified and c not in specified:
                    continue
                alerts.append(f"🌍 GEO ANOMALY: New connection from {c}")

        if rules.get("new_connection", True):
            prev_conns = set(
                (c["local"], c["remote"]) for c in self._state.get("last_connections", [])
            )
            curr_conns = set((c["local"], c["remote"]) for c in connections)
            new_conns = curr_conns - prev_conns
            if new_conns:
                alerts.append(f"🔗 NEW CONNECTIONS: {len(new_conns)} new socket(s) detected")

        # Send alerts
        if alerts and config.get("alerts_enabled", True):
            message = "\n".join(alerts[:20])  # cap alert length
            send_alert(config, message, level="warning")
            self._save_alert_log(alerts)

        # Save snapshot for history
        snapshot = {
            "timestamp": now,
            "connections": connections,
            "ports": ports,
            "adapters": adapters,
            "vpns": vpns,
            "countries": countries,
        }
        self._snapshot(snapshot)

        # Update state for next comparison
        new_state = {
            "last_connections": connections,
            "last_ports": curr_ports,
            "last_countries": list(curr_countries),
            "last_adapters": [a["name"] for a in adapters],
            "first_seen": self._state.get("first_seen", now),
            "last_tick": now,
        }
        with self._lock:
            self._state = new_state
        save_state(new_state)

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #
    @staticmethod
    def _extract_remote_ips(connections: List[Dict[str, Any]]) -> List[str]:
        ips: Set[str] = set()
        for c in connections:
            remote = c.get("remote", "N/A")
            if remote and remote != "N/A" and ":" in remote:
                ip = remote.rsplit(":", 1)[0]
                if ip not in ("0.0.0.0", "127.0.0.1", "::1", "::"):
                    ips.add(ip)
        return list(ips)

    def _lookup_countries_limited(
        self, ips: List[str], config: Dict[str, Any]
    ) -> Dict[str, str]:
        """Return {ip: country} with rate limiting to avoid GeoIP API abuse."""
        result: Dict[str, str] = {}
        min_interval = 1.0 / max(float(config.get("geoip_rate_limit", 1)), 0.1)
        for ip in ips[:15]:  # cap to avoid hammering free GeoIP API
            with self._geoip_lock:
                elapsed = time.time() - self._last_geoip_call
                if elapsed < min_interval:
                    time.sleep(min_interval - elapsed)
                try:
                    data = geoip_lookup(ip)
                    result[ip] = data.get("country_code") or data.get("country") or "UNKNOWN"
                except Exception:
                    result[ip] = "UNKNOWN"
                self._last_geoip_call = time.time()
        return result

    def _snapshot(self, data: Dict[str, Any]) -> None:
        """Append a timestamped snapshot to history."""
        HISTORY_DIR.mkdir(parents=True, exist_ok=True)
        stamp = data["timestamp"].replace(":", "-").replace(".", "-")
        path = HISTORY_DIR / f"snapshot_{stamp}.json"
        try:
            with path.open("w", encoding="utf-8") as fh:
                json.dump(data, fh, indent=2, default=str)
        except OSError:
            pass
        # Rotate old snapshots
        max_files = int(config_get(self.config, "max_history_files", 500))
        self._rotate_files(HISTORY_DIR, "snapshot_", max_files)

    def _save_alert_log(self, alerts: List[str]) -> None:
        LOGS_DIR.mkdir(parents=True, exist_ok=True)
        path = LOGS_DIR / "alerts.log"
        stamp = datetime.now().isoformat()
        line = f"[{stamp}] " + " | ".join(alerts[:10]) + "\n"
        try:
            with path.open("a", encoding="utf-8") as fh:
                fh.write(line)
        except OSError:
            pass
        self._rotate_files(LOGS_DIR, "alerts.log", 1)

    @staticmethod
    def _rotate_files(directory: Path, prefix: str, keep: int) -> None:
        """Keep only the newest `keep` files matching prefix."""
        try:
            files = sorted(
                [f for f in directory.iterdir() if f.name.startswith(prefix) and f.is_file()],
                key=lambda f: f.stat().st_mtime,
                reverse=True,
            )
            for f in files[keep:]:
                try:
                    f.unlink()
                except OSError:
                    pass
        except OSError:
            pass

    def _log_error(self, message: str) -> None:
        LOGS_DIR.mkdir(parents=True, exist_ok=True)
        path = LOGS_DIR / "errors.log"
        stamp = datetime.now().isoformat()
        try:
            with path.open("a", encoding="utf-8") as fh:
                fh.write(f"[{stamp}] {message}\n")
        except OSError:
            pass


def config_get(config: Dict[str, Any], key: str, default: Any = None) -> Any:
    """Safe config getter."""
    return config.get(key, default)


# Singleton-ish helper for CLI
_daemon: Optional[NetMonitorDaemon] = None
_daemon_lock = threading.Lock()


def get_daemon(config: Optional[Dict[str, Any]] = None) -> NetMonitorDaemon:
    global _daemon
    with _daemon_lock:
        if _daemon is None:
            _daemon = NetMonitorDaemon(config)
        elif config is not None:
            _daemon.config = config
    return _daemon
