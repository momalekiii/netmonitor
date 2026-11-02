"""JA3/JA4 SSL fingerprinting feature.

Detects client TLS fingerprints to identify bots/scanners.
Non-destructive: passive observation only.
"""

from typing import Any, Dict

from ..config import DEFAULT_CONFIG


class JA3FingerprintingFeature:
    name = "ja3_fingerprinting"
    description = "JA3/JA4 TLS fingerprinting for bot detection"
    default_enabled = False
    requires_root = False

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.enabled = config.get("features", {}).get("ja3_fingerprinting", False)
        self.known_fingerprints = config.get("known_ja3_fingerprints", {})

    def is_enabled(self) -> bool:
        return self.enabled

    def install(self) -> Dict[str, Any]:
        changes = []
        if self.enabled:
            changes.append("Tracking " + str(len(self.known_fingerprints)) + " known fingerprint(s)")
        return {"ok": True, "message": "JA3 fingerprinting feature configured", "changes": changes}

    def analyze_fingerprint(self, fingerprint: str) -> Dict[str, Any]:
        """Analyze a JA3 fingerprint.

        Returns whether it's known/suspicious without modifying anything.
        """
        known = fingerprint in self.known_fingerprints
        return {
            "fingerprint": fingerprint,
            "known": known,
            "label": self.known_fingerprints.get(fingerprint, "unknown"),
            "suspicious": not known,
        }
