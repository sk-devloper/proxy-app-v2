"""Anomaly detection for J.A.R.V.I.S. Proxy.

Detects traffic spikes per client IP or target domain using a rolling-window
request-rate check.  When a key exceeds the configured threshold, the detector
returns True and the proxy can fire an alert via alerting.py.

Config section (config.yaml)::

    anomaly:
      enabled: true
      window_seconds: 60       # rolling window length
      threshold_rps: 200       # max requests per window before anomaly fires
      cooldown_seconds: 300    # min seconds between repeated alerts for same key
"""
from __future__ import annotations

import time
from collections import defaultdict, deque
from typing import Dict


class AnomalyDetector:
    """Rolling-window request-rate anomaly detector."""

    def __init__(
        self,
        window_seconds: int = 60,
        threshold_rps: int = 200,
        cooldown_seconds: int = 300,
    ):
        self.window_seconds   = window_seconds
        self.threshold_rps    = threshold_rps
        self.cooldown_seconds = cooldown_seconds

        self._counters: Dict[str, deque] = defaultdict(deque)
        self._last_alert:  Dict[str, float] = {}

    def record(self, key: str) -> bool:
        """Record one event for *key* and return True if an anomaly is detected.

        An anomaly fires when the number of events inside the rolling window
        reaches *threshold_rps* AND the cooldown since the last alert for this
        key has expired.
        """
        now    = time.monotonic()
        window = self._counters[key]
        cutoff = now - self.window_seconds

        # Evict expired entries O(1) amortised
        while window and window[0] <= cutoff:
            window.popleft()

        window.append(now)

        if len(window) < self.threshold_rps:
            return False

        last = self._last_alert.get(key, 0.0)
        if now - last < self.cooldown_seconds:
            return False

        self._last_alert[key] = now
        return True

    @classmethod
    def from_config(cls, config: dict) -> "AnomalyDetector":
        """Build from the 'anomaly' section of config.yaml."""
        a = config.get("anomaly", {})
        return cls(
            window_seconds   = int(a.get("window_seconds",   60)),
            threshold_rps    = int(a.get("threshold_rps",   200)),
            cooldown_seconds = int(a.get("cooldown_seconds", 300)),
        )
