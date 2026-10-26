"""
Configurable HTTP Rate-Anomaly Detection Engine.

Monitors request velocity and burst patterns per client identity across rolling/sliding
time windows. Detects excessive rates and short-duration volumetric bursts while preventing
alert flooding via debounced cooldowns. Safely bounds memory and tracking entries to protect
against memory-exhaustion DoS attacks. Separates anomaly detection from enforcement.
"""

import os
import time
import uuid
import threading
from typing import Dict, List, Optional, Tuple, Set, Any


class RateAnomalyConfig:
    """Configurable parameters for HTTP request rate-anomaly detection."""

    def __init__(self):
        # Enable or disable rate-anomaly detector
        self.enabled: bool = os.getenv("RATE_ANOMALY_ENABLED", "true").lower() in ("1", "true", "yes")

        # Rolling time window for request count analysis (in seconds)
        self.window_seconds: float = float(os.getenv("RATE_ANOMALY_WINDOW_SECONDS", "10.0"))

        # Request count threshold within window_seconds to trigger an anomaly alert
        self.threshold: int = int(os.getenv("RATE_ANOMALY_THRESHOLD", "15"))

        # Burst detection: short rolling window (in seconds) to capture rapid spikes
        self.burst_window_seconds: float = float(os.getenv("RATE_ANOMALY_BURST_WINDOW_SECONDS", "2.0"))

        # Threshold of requests within burst_window_seconds to flag a sudden burst
        self.burst_threshold: int = int(os.getenv("RATE_ANOMALY_BURST_THRESHOLD", "8"))

        # Cooldown period (in seconds) suppressing repeated alerts for the same source identity
        self.cooldown_seconds: float = float(os.getenv("RATE_ANOMALY_COOLDOWN_SECONDS", "30.0"))

        # Maximum tracked client identities to bound memory usage and prevent tracking exhaustion
        self.max_tracked_identities: int = int(os.getenv("RATE_ANOMALY_MAX_IDENTITIES", "2000"))

        # Endpoints excluded from rate-anomaly monitoring (e.g. routine health checks)
        excluded_str = os.getenv("RATE_ANOMALY_EXCLUDED_PATHS", "/health,/healthz,/actuator/health,/favicon.ico")
        self.excluded_paths: Set[str] = {p.strip().lower() for p in excluded_str.split(",") if p.strip()}

        # IP addresses excluded from rate-anomaly monitoring (e.g. trusted internal telemetry)
        excluded_ips_str = os.getenv("RATE_ANOMALY_EXCLUDED_IPS", "")
        self.excluded_ips: Set[str] = {ip.strip() for ip in excluded_ips_str.split(",") if ip.strip()}


class RateAnomalyTracker:
    """
    Thread-safe, sliding-window HTTP rate-anomaly detection engine.
    Computes rolling request rates per source identity, checks threshold and burst criteria,
    applies cooldown deduplication, and bounds internal state memory.
    """

    def __init__(self, config: Optional[RateAnomalyConfig] = None):
        self.config = config or RateAnomalyConfig()
        # source_ip -> list of request timestamps (float)
        self.requests: Dict[str, List[float]] = {}
        # source_ip -> float (timestamp of last emitted anomaly alert)
        self.last_alert_time: Dict[str, float] = {}
        # source_ip -> float (timestamp of last seen request, used for LRU eviction)
        self.last_seen: Dict[str, float] = {}
        self._lock = threading.Lock()

    def is_path_excluded(self, path: str) -> bool:
        """Check if requested path is on the health-check exclusion list."""
        if not path:
            return False
        clean_path = path.split("?")[0].strip().lower()
        return clean_path in self.config.excluded_paths

    def is_ip_excluded(self, source_ip: str) -> bool:
        """Check if source IP is on the explicit exclusion list."""
        if not source_ip:
            return False
        return source_ip.strip() in self.config.excluded_ips

    def record_request(
        self,
        source_ip: str,
        path: str = "/",
        method: str = "GET",
        current_time: Optional[float] = None
    ) -> Tuple[bool, Optional[Dict[str, Any]]]:
        """
        Record an incoming HTTP request and evaluate rate-anomaly indicators.

        Returns:
            (is_anomaly, anomaly_details_dict)
            If an anomaly is detected and cooldown has elapsed: returns (True, details).
            If no anomaly or during cooldown: returns (False, None).
        """
        if not self.config.enabled:
            return False, None

        if self.is_path_excluded(path) or self.is_ip_excluded(source_ip):
            return False, None

        now = current_time if current_time is not None else time.time()
        max_window = max(self.config.window_seconds, self.config.burst_window_seconds)
        window_start = now - self.config.window_seconds
        burst_start = now - self.config.burst_window_seconds

        with self._lock:
            # 1. Bounded memory defense: If tracking capacity reached and client is new,
            # perform pruning. If still full, evict the least recently used key.
            if source_ip not in self.requests and len(self.requests) >= self.config.max_tracked_identities:
                self._prune_stale(now, max_window)
                if len(self.requests) >= self.config.max_tracked_identities:
                    # LRU Eviction: remove oldest seen key
                    oldest_ip = min(self.last_seen.keys(), key=lambda k: self.last_seen[k], default=None)
                    if oldest_ip and oldest_ip != source_ip:
                        self.requests.pop(oldest_ip, None)
                        self.last_alert_time.pop(oldest_ip, None)
                        self.last_seen.pop(oldest_ip, None)

            # Update last seen timestamp
            self.last_seen[source_ip] = now

            # 2. Append timestamp and prune history older than max_window
            history = self.requests.get(source_ip, [])
            cutoff = now - max_window
            active = [t for t in history if t > cutoff]
            active.append(now)
            self.requests[source_ip] = active

            # 3. Compute window metrics
            window_requests = [t for t in active if t > window_start]
            window_count = len(window_requests)

            burst_requests = [t for t in active if t > burst_start]
            burst_count = len(burst_requests)

            is_burst = burst_count >= self.config.burst_threshold
            is_threshold_crossed = window_count >= self.config.threshold

            if not (is_threshold_crossed or is_burst):
                return False, None

            # 4. Debounced cooldown check: Avoid creating one alert for every subsequent request
            last_alert = self.last_alert_time.get(source_ip, 0.0)
            if now - last_alert < self.config.cooldown_seconds:
                # Still within cooldown window; deduplicate alert
                return False, None

            # Register alert timestamp
            self.last_alert_time[source_ip] = now

            # 5. Determine severity and format structured evidence
            # Repeated bursts or rate significantly above threshold escalate severity to HIGH
            if is_burst and window_count >= self.config.threshold * 1.5:
                severity = "HIGH"
            elif is_burst or window_count >= self.config.threshold * 2:
                severity = "HIGH"
            else:
                severity = "MEDIUM"

            calc_rate = round(window_count / max(self.config.window_seconds, 1.0), 2)
            burst_rate = round(burst_count / max(self.config.burst_window_seconds, 0.1), 2)

            if is_burst and is_threshold_crossed:
                msg = (
                    f"HTTP request rate anomaly and sudden burst detected from {source_ip}: "
                    f"{burst_count} reqs in {self.config.burst_window_seconds}s (burst rate: {burst_rate} req/s), "
                    f"{window_count} reqs in {self.config.window_seconds}s (threshold: {self.config.threshold})"
                )
            elif is_burst:
                msg = (
                    f"HTTP request burst anomaly detected from {source_ip}: "
                    f"{burst_count} reqs in {self.config.burst_window_seconds}s "
                    f"(burst threshold: {self.config.burst_threshold}, burst rate: {burst_rate} req/s)"
                )
            else:
                msg = (
                    f"HTTP request rate anomaly detected from {source_ip}: "
                    f"{window_count} requests in {self.config.window_seconds}s window "
                    f"(threshold: {self.config.threshold}, rate: {calc_rate} req/s)"
                )

            evidence = {
                "source_ip": source_ip,
                "window_count": window_count,
                "window_seconds": self.config.window_seconds,
                "configured_threshold": self.config.threshold,
                "burst_count": burst_count,
                "burst_window_seconds": self.config.burst_window_seconds,
                "configured_burst_threshold": self.config.burst_threshold,
                "is_burst": is_burst,
                "effective_rate_rps": calc_rate,
                "burst_rate_rps": burst_rate,
                "cooldown_seconds": self.config.cooldown_seconds,
                "mitre_technique": "T1499",
                "mitre_name": "Endpoint Denial of Service",
                "classification": "SINGLE_SOURCE_RATE_ANOMALY",
                "note": "Single high request count detected; not confirmed distributed denial-of-service (DDoS)."
            }

            anomaly_details = {
                "message": msg,
                "severity": severity,
                "source_ip": source_ip,
                "affected_endpoint": path,
                "http_method": method.upper(),
                "request_count": window_count,
                "measurement_window_seconds": self.config.window_seconds,
                "configured_threshold": self.config.threshold,
                "detection_category": "RATE_ANOMALY",
                "detection_method": "SLIDING_WINDOW",
                "is_burst": is_burst,
                "evidence": evidence
            }
            return True, anomaly_details

    def reset_ip(self, source_ip: str):
        """Administrative reset of rate-anomaly tracking history and alerts for an IP."""
        with self._lock:
            self.requests.pop(source_ip, None)
            self.last_alert_time.pop(source_ip, None)
            self.last_seen.pop(source_ip, None)

    def get_tracked_count(self) -> int:
        """Return the number of currently tracked source identities."""
        with self._lock:
            return len(self.requests)

    def _prune_stale(self, now: float, max_window: float):
        """Prune tracking keys whose timestamps are entirely outside the active evaluation window."""
        cutoff = now - max_window
        stale_ips = [
            ip for ip, timestamps in self.requests.items()
            if not timestamps or timestamps[-1] <= cutoff
        ]
        for ip in stale_ips:
            self.requests.pop(ip, None)
            self.last_seen.pop(ip, None)

        # Also purge old alert timestamps past 2x cooldown
        alert_cutoff = now - (self.config.cooldown_seconds * 2)
        stale_alerts = [ip for ip, ts in self.last_alert_time.items() if ts <= alert_cutoff]
        for ip in stale_alerts:
            self.last_alert_time.pop(ip, None)
