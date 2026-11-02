"""Bandwidth anomaly detection feature.

Detects sudden spikes in network traffic compared to baseline.
Non-destructive: read-only on interface counters.
"""

from typing import Any, Dict

from ..config import DEFAULT_CONFIG


class BandwidthAnomalyFeature:
    name = "bandwidth_anomaly"
    description = "Bandwidth anomaly detection vs baseline"
    default_enabled = False
    requires_root = False

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.enabled = config.get("features", {}).get("bandwidth_anomaly", False)
        self.baseline_mb = config.get("bandwidth_baseline_mb", 0)
        self.threshold = config.get("bandwidth_anomaly_threshold", 3.0)

    def is_enabled(self) -> bool:
        return self.enabled

    def install(self) -> Dict[str, Any]:
        changes = []
        if self.enabled:
            changes.append("Baseline: " + str(self.baseline_mb) + " MB")
            changes.append("Anomaly threshold: " + str(self.threshold) + "x baseline")
        return {"ok": True, "message": "Bandwidth anomaly feature configured", "changes": changes}

    def check_bandwidth(self) -> Dict[str, Any]:
        """Check current bandwidth against baseline.

        Returns anomaly status without modifying anything.
        """
        try:
            import psutil
            counters = psutil.net_io_counters()
            total_mb = (counters.bytes_sent + counters.bytes_recv) / (1024 * 1024)
        except Exception:
            total_mb = 0

        anomaly = False
        ratio = 0
        if self.baseline_mb > 0:
            ratio = total_mb / self.baseline_mb
            anomaly = ratio > self.threshold

        return {
            "current_mb": round(total_mb, 2),
            "baseline_mb": self.baseline_mb,
            "ratio": round(ratio, 2),
            "anomaly": anomaly,
            "threshold": self.threshold,
        }
