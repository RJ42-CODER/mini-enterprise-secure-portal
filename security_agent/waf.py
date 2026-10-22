import os
import re
import time
import urllib.parse
import threading
from typing import Optional, Dict, Any, Tuple, Set, List
from flask import Response, Request

class WAFConfig:
    """Configurable Web Application Firewall parameters."""

    def __init__(self):
        # Mode: 'BLOCK' (enforce and reject attacks) or 'MONITOR' (audit and alert only)
        self.mode: str = os.getenv("WAF_MODE", "BLOCK").upper().strip()
        if self.mode not in ("BLOCK", "MONITOR", "AUDIT"):
            self.mode = "BLOCK"

        # Maximum permitted HTTP request body size (in bytes). Default: 1 MB
        self.max_content_length: int = int(os.getenv("WAF_MAX_CONTENT_LENGTH", "1048576"))

        # Whitelist of allowed HTTP request methods
        methods_str = os.getenv("WAF_ALLOWED_METHODS", "GET,POST,HEAD")
        self.allowed_methods: Set[str] = {m.strip().upper() for m in methods_str.split(",") if m.strip()}

        # Rate limiting: requests per minute per source IP
        self.rate_limit_rpm: int = int(os.getenv("WAF_RATE_LIMIT_RPM", "120"))
        self.rate_limit_burst: int = int(os.getenv("WAF_RATE_LIMIT_BURST", "30"))

        # Authentication brute-force progressive lockout policy
        self.auth_lockout_threshold: int = int(os.getenv("WAF_AUTH_LOCKOUT_THRESHOLD", "3"))
        self.auth_lockout_seconds: int = int(os.getenv("WAF_AUTH_LOCKOUT_SECONDS", "60"))
        self.auth_lockout_max_seconds: int = int(os.getenv("WAF_AUTH_LOCKOUT_MAX_SECONDS", "3600"))
        self.auth_decay_seconds: int = int(os.getenv("WAF_AUTH_DECAY_SECONDS", "300"))

        # Directory discovery (DIR_FUZZ) and active throttling policy
        self.dir_fuzz_threshold: int = int(os.getenv("DIR_FUZZ_THRESHOLD", "5"))
        self.dir_fuzz_window_seconds: int = int(os.getenv("DIR_FUZZ_WINDOW_SECONDS", "60"))
        self.dir_fuzz_cooldown_seconds: int = int(os.getenv("DIR_FUZZ_COOLDOWN_SECONDS", "10"))
        self.dir_fuzz_throttle_seconds: int = int(os.getenv("WAF_DIR_FUZZ_THROTTLE_SECONDS", "60"))


class RateLimiter:
    """Thread-safe sliding-window rate limiter per source IP."""

    def __init__(self, limit_per_minute: int = 120):
        self.limit = limit_per_minute
        self.requests: Dict[str, List[float]] = {}
        self._lock = threading.Lock()

    def is_allowed(self, ip: str) -> bool:
        now = time.time()
        window_start = now - 60.0
        with self._lock:
            history = [t for t in self.requests.get(ip, []) if t > window_start]
            if len(history) >= self.limit:
                self.requests[ip] = history
                return False
            history.append(now)
            self.requests[ip] = history

            # Prune stale tracking keys periodically
            if len(self.requests) > 2000:
                self._prune_stale(now)
            return True

    def _prune_stale(self, now: float):
        window_start = now - 60.0
        stale = [k for k, v in self.requests.items() if not v or v[-1] < window_start]
        for k in stale:
            self.requests.pop(k, None)


class BruteForceProtector:
    """
    Tracks authentication failures and applies progressive client IP lockout.
    Escalates lockout duration exponentially with repeated offenses:
      - Tier 1: base_lockout (e.g. 60s)
      - Tier 2: base_lockout * 2 (e.g. 120s)
      - Tier 3: base_lockout * 4 (e.g. 240s)
      up to max_lockout_seconds.
    """

    def __init__(
        self,
        threshold: int = 3,
        lockout_seconds: int = 60,
        decay_seconds: int = 300,
        max_lockout_seconds: int = 3600
    ):
        self.threshold = threshold
        self.lockout_seconds = lockout_seconds
        self.decay_seconds = decay_seconds
        self.max_lockout_seconds = max_lockout_seconds
        self.failures: Dict[str, List[float]] = {}
        self.lockouts: Dict[str, float] = {}  # ip -> lockout_until
        self.lockout_tiers: Dict[str, int] = {}  # ip -> tier (1, 2, 3...)
        self.total_lockouts: Dict[str, int] = {}  # ip -> count of times locked out
        self._lock = threading.Lock()

    def is_locked_out(self, ip: str) -> Tuple[bool, int]:
        """Check if source IP is currently under active authentication lockout."""
        now = time.time()
        with self._lock:
            locked_until = self.lockouts.get(ip, 0)
            if now < locked_until:
                remaining = int(locked_until - now)
                return True, max(1, remaining)
            elif ip in self.lockouts:
                del self.lockouts[ip]
            return False, 0

    def get_tier(self, ip: str) -> int:
        """Return the current progressive lockout tier for this IP."""
        with self._lock:
            return self.lockout_tiers.get(ip, 0)

    def record_failure(self, ip: str) -> Tuple[int, bool]:
        """
        Record an auth failure.
        Applies progressive exponential lockout if threshold is reached.
        Returns (current_failure_count, is_now_locked_out).
        """
        now = time.time()
        with self._lock:
            recent = [t for t in self.failures.get(ip, []) if now - t < self.decay_seconds]
            recent.append(now)
            self.failures[ip] = recent
            count = len(recent)

            if count >= self.threshold:
                current_tier = self.lockout_tiers.get(ip, 0) + 1
                self.lockout_tiers[ip] = current_tier
                self.total_lockouts[ip] = self.total_lockouts.get(ip, 0) + 1

                # Exponential progressive escalation: base * 2^(tier - 1)
                multiplier = 2 ** (current_tier - 1)
                duration = min(self.lockout_seconds * multiplier, self.max_lockout_seconds)
                self.lockouts[ip] = now + duration
                return count, True

            return count, False

    def record_success(self, ip: str):
        """Clear failure history and reset progressive lockout tier upon verified successful authentication."""
        with self._lock:
            self.failures.pop(ip, None)
            self.lockouts.pop(ip, None)
            self.lockout_tiers.pop(ip, None)

    def reset_ip(self, ip: str):
        """Administrative rollback / release of lockout for a given IP."""
        with self._lock:
            self.failures.pop(ip, None)
            self.lockouts.pop(ip, None)
            self.lockout_tiers.pop(ip, None)
            self.total_lockouts.pop(ip, None)

    def get_active_lockouts(self) -> List[Dict[str, Any]]:
        """Return list of currently locked out IPs with remaining seconds and tier."""
        now = time.time()
        active = []
        with self._lock:
            for ip, until in list(self.lockouts.items()):
                if now < until:
                    active.append({
                        "ip": ip,
                        "remaining_seconds": int(until - now),
                        "tier": self.lockout_tiers.get(ip, 1),
                        "total_lockouts": self.total_lockouts.get(ip, 1)
                    })
                else:
                    self.lockouts.pop(ip, None)
        return active


class DirectoryFuzzTracker:
    """
    Tracks repeated HTTP 404 Not Found responses per client IP to detect directory
    enumeration / path fuzzing attacks (DIR_FUZZ) in a sliding time window.
    Applies active progressive throttling to quarantine fuzzing clients and protect backend resources.
    """

    def __init__(
        self,
        threshold: int = 5,
        window_seconds: int = 60,
        cooldown_seconds: int = 10,
        throttle_seconds: int = 60
    ):
        self.threshold = threshold
        self.window_seconds = window_seconds
        self.cooldown_seconds = cooldown_seconds
        self.throttle_seconds = throttle_seconds
        # ip -> list of (timestamp, path)
        self.probes: Dict[str, List[Tuple[float, str]]] = {}
        # (ip, path) -> timestamp of last explicit path alert
        self.explicit_path_alerts: Dict[Tuple[str, str], float] = {}
        # ip -> timestamp of last threshold burst alert
        self.last_alert_time: Dict[str, float] = {}
        # Active throttling: ip -> float (throttled_until)
        self.throttles: Dict[str, float] = {}
        # ip -> throttle_tier (1, 2...)
        self.throttle_tiers: Dict[str, int] = {}
        self._lock = threading.Lock()

    def is_throttled(self, source_ip: str) -> Tuple[bool, int, int]:
        """Check if source IP is actively throttled due to directory fuzzing."""
        now = time.time()
        with self._lock:
            until = self.throttles.get(source_ip, 0.0)
            if now < until:
                remaining = int(until - now)
                tier = self.throttle_tiers.get(source_ip, 1)
                return True, max(1, remaining), tier
            elif source_ip in self.throttles:
                del self.throttles[source_ip]
            return False, 0, 0

    def record_404_probe(self, source_ip: str, path: str) -> Tuple[bool, Optional[Dict[str, Any]]]:
        """
        Record a 404 response for the given source IP and path.
        Returns (detected, info_dict) if the distinct 404 path count reaches or exceeds
        the threshold within window_seconds.
        Activates progressive throttling to block subsequent requests.
        """
        now = time.time()
        with self._lock:
            history = self.probes.get(source_ip, [])
            window_start = now - self.window_seconds
            # Keep only probes within the sliding time window
            active = [(ts, p) for ts, p in history if ts > window_start]
            active.append((now, path))
            self.probes[source_ip] = active

            # Periodically prune inactive client tracking entries
            if len(self.probes) > 2000:
                self._prune_stale(now)

            # Determine distinct probed paths (preserving discovery order)
            distinct_paths = list(dict.fromkeys(p for _, p in active))
            distinct_count = len(distinct_paths)

            if distinct_count >= self.threshold:
                # Apply / escalate directory fuzzing throttle
                tier = self.throttle_tiers.get(source_ip, 0) + 1
                self.throttle_tiers[source_ip] = tier
                duration = min(self.throttle_seconds * (2 ** (tier - 1)), 3600)
                self.throttles[source_ip] = now + duration

                last_alert = self.last_alert_time.get(source_ip, 0)
                if now - last_alert < self.cooldown_seconds:
                    # Debounced within cooldown window
                    return False, None

                self.last_alert_time[source_ip] = now
                msg = (
                    f"Directory discovery / fuzzing attack detected "
                    f"({distinct_count} distinct 404 paths within {self.window_seconds}s) from {source_ip}; "
                    f"Throttling applied for {duration}s (Tier {tier})"
                )
                info = {
                    "message": msg,
                    "severity": "HIGH",
                    "distinct_count": distinct_count,
                    "probed_paths": distinct_paths,
                    "throttle_duration": duration,
                    "throttle_tier": tier
                }
                return True, info

            return False, None

    def record_recon_scanner(self, source_ip: str, tool: str) -> int:
        """Immediately throttle an automated recon scanner tool."""
        now = time.time()
        with self._lock:
            tier = self.throttle_tiers.get(source_ip, 0) + 1
            self.throttle_tiers[source_ip] = tier
            duration = min(self.throttle_seconds * (2 ** (tier - 1)), 3600)
            self.throttles[source_ip] = now + duration
            return duration

    def reset_ip(self, source_ip: str):
        """Reset probe history, alerts, and throttling for a specific IP (rollback)."""
        with self._lock:
            self.probes.pop(source_ip, None)
            self.last_alert_time.pop(source_ip, None)
            self.throttles.pop(source_ip, None)
            self.throttle_tiers.pop(source_ip, None)
            keys_to_remove = [k for k in self.explicit_path_alerts if k[0] == source_ip]
            for k in keys_to_remove:
                del self.explicit_path_alerts[k]

    def get_active_throttles(self) -> List[Dict[str, Any]]:
        """Return list of currently throttled IPs."""
        now = time.time()
        active = []
        with self._lock:
            for ip, until in list(self.throttles.items()):
                if now < until:
                    active.append({
                        "ip": ip,
                        "remaining_seconds": int(until - now),
                        "tier": self.throttle_tiers.get(ip, 1)
                    })
                else:
                    self.throttles.pop(ip, None)
        return active

    def _prune_stale(self, now: float):
        window_start = now - self.window_seconds
        stale_ips = [
            ip for ip, probes in self.probes.items()
            if not probes or probes[-1][0] <= window_start
        ]
        for ip in stale_ips:
            self.probes.pop(ip, None)
            self.last_alert_time.pop(ip, None)

        cooldown_cutoff = now - max(self.window_seconds, self.cooldown_seconds * 2)
        stale_alerts = [
            k for k, ts in self.explicit_path_alerts.items()
            if ts <= cooldown_cutoff
        ]
        for k in stale_alerts:
            self.explicit_path_alerts.pop(k, None)


class WAFInspector:
    """
    Application-level request inspection and policy enforcement engine.
    Inspects HTTP methods, content sizes, rate limits, and malicious payload patterns.
    """

    # SQL Injection detection patterns
    SQLI_PATTERNS = [
        re.compile(r"('|\%27)\s*(or|and)\s*('|\%27)?\d+('|\%27)?\s*=\s*('|\%27)?\d+", re.IGNORECASE),
        re.compile(r"union(\s+all)?\s+select", re.IGNORECASE),
        re.compile(r"(;\s*|\s+)select(\s+.+)?\s+from", re.IGNORECASE),
        re.compile(r"(;\s*|\s+)insert\s+into", re.IGNORECASE),
        re.compile(r"(;\s*|\s+)drop\s+table", re.IGNORECASE),
        re.compile(r"('|\%27|;|\s)--", re.IGNORECASE),
        re.compile(r"--\s*$", re.MULTILINE),
        re.compile(r"/\*.*?\*/", re.DOTALL),
        re.compile(r"(exec(\s+xp_)?|benchmark\s*\(|sleep\s*\(|waitfor\s+delay)", re.IGNORECASE),
        re.compile(r"information_schema", re.IGNORECASE),
    ]

    # Command Injection detection patterns
    CMDI_PATTERNS = [
        re.compile(r"[;&|]\s*(whoami|id|cat(\s+|\b)|dir(\s+|\b)|ls(\s+|\b)|uname|powershell|bash|sh)", re.IGNORECASE),
        re.compile(r"\$\(\s*(whoami|id|uname|cat).*?\)", re.IGNORECASE),
        re.compile(r"`\s*(whoami|id|uname|cat).*?`", re.IGNORECASE),
        re.compile(r"(/bin/(sh|bash)|cmd\.exe|powershell(\.exe)?)", re.IGNORECASE),
    ]

    # Path Traversal patterns
    TRAVERSAL_PATTERNS = [
        re.compile(r"(\.\./|\.\.\\|\%2e\%2e\%2f|\%2e\%2e/|\%2e\%2e\\)", re.IGNORECASE),
        re.compile(r"(\b|/)(etc/(passwd|shadow|hosts)|win\.ini|boot\.ini)", re.IGNORECASE),
    ]

    # Cross-Site Scripting (XSS) patterns
    XSS_PATTERNS = [
        re.compile(r"<\s*script[^>]*>.*?</\s*script\s*>", re.IGNORECASE | re.DOTALL),
        re.compile(r"<\s*script[^>]*>", re.IGNORECASE),
        re.compile(r"javascript\s*:\s*.*", re.IGNORECASE),
        re.compile(r"<\s*img[^>]+(onerror|onload)\s*=", re.IGNORECASE),
        re.compile(r"<\s*(iframe|object|embed|svg)[^>]*>", re.IGNORECASE),
        re.compile(r"(alert|prompt|confirm)\s*\([^\)]*\)", re.IGNORECASE),
        re.compile(r"document\.(cookie|location|write)", re.IGNORECASE),
        re.compile(r"on(click|load|error|mouseover|focus|blur|submit)\s*=", re.IGNORECASE),
    ]

    # Reconnaissance tools and sensitive paths
    SCANNER_AGENTS = ["nmap", "nikto", "masscan", "zgrab", "gobuster", "dirbuster", "ffuf", "sqlmap"]
    SENSITIVE_PATHS = [
        "/.env", "/.git", "/.svn", "/.htaccess", "/.aws", "/.ssh",
        "/wp-admin", "/wp-login", "/wp-content", "/xmlrpc.php",
        "/phpmyadmin", "/pma", "/adminer",
        "/config.php", "/configuration.php", "/settings.py", "/database.yml",
        "/backup.zip", "/backup.tar", "/backup.sql", "/dump.sql",
        "/admin.php", "/administrator", "/webadmin", "/login.php",
        "/actuator", "/actuator/env", "/actuator/health",
        "/server-status", "/server-info",
        "/phpinfo.php", "/info.php",
        "/console", "/shell", "/c99.php"
    ]

    def __init__(self, config: Optional[WAFConfig] = None, fuzz_tracker: Optional[DirectoryFuzzTracker] = None):
        self.config = config or WAFConfig()
        self.rate_limiter = RateLimiter(self.config.rate_limit_rpm)
        self.brute_force_protector = BruteForceProtector(
            threshold=self.config.auth_lockout_threshold,
            lockout_seconds=self.config.auth_lockout_seconds,
            decay_seconds=self.config.auth_decay_seconds,
            max_lockout_seconds=self.config.auth_lockout_max_seconds
        )
        self.fuzz_tracker = fuzz_tracker or DirectoryFuzzTracker(
            threshold=self.config.dir_fuzz_threshold,
            window_seconds=self.config.dir_fuzz_window_seconds,
            cooldown_seconds=self.config.dir_fuzz_cooldown_seconds,
            throttle_seconds=self.config.dir_fuzz_throttle_seconds
        )

    def is_explicit_suspicious_path(self, path: str) -> Tuple[bool, Optional[str]]:
        """Check whether path matches known explicit suspicious sensitive indicators."""
        norm = self.normalize_string(path).lower()
        for fpath in self.SENSITIVE_PATHS:
            if fpath in norm:
                return True, fpath
        suspicious_extensions = (
            ".env", ".git", ".sql", ".bak", ".backup", ".old", ".conf",
            ".ini", ".yml", ".yaml", ".log", ".tar.gz", ".zip"
        )
        base_path = norm.split("?")[0].strip()
        for ext in suspicious_extensions:
            if base_path.endswith(ext):
                return True, ext
        return False, None

    def normalize_string(self, value: str) -> str:
        """Apply safe URL unquoting and lowercase conversion."""
        if not value:
            return ""
        try:
            # Unquote up to 2 times for double-encoding bypass attempts
            unquoted = urllib.parse.unquote(urllib.parse.unquote(value))
        except Exception:
            unquoted = value
        # Strip null bytes
        return unquoted.replace("\x00", "")

    def inspect_request(
        self,
        source_ip: str,
        path: str,
        method: str,
        headers: Dict[str, str],
        query_string: str = "",
        body: str = "",
        content_length: Optional[int] = None
    ) -> Optional[Dict[str, Any]]:
        """
        Evaluate full HTTP request against WAF policies.
        Returns a dictionary with detection details if a rule is triggered, or None if benign.
        Enforces perimeter rejection with structured mitigation verification evidence.
        """
        # 0. Active Directory Fuzzing Throttling / Quarantine Check
        if self.fuzz_tracker:
            is_throttled, remaining, tier = self.fuzz_tracker.is_throttled(source_ip)
            if is_throttled:
                return {
                    "blocked": True,
                    "status_code": 429,
                    "rule": "DIR_FUZZ_THROTTLED",
                    "signature": "DIR_FUZZ",
                    "severity": "HIGH",
                    "message": f"Source IP '{source_ip}' is throttled due to automated directory fuzzing activity ({remaining}s remaining, Tier {tier})",
                    "metadata": {
                        "source_ip": source_ip,
                        "retry_after_seconds": remaining,
                        "throttle_tier": tier,
                        "policy": "directory_fuzzing_throttling"
                    },
                    "client_message": f"429 Too Many Requests: Client IP temporarily quarantined due to directory fuzzing. Retry in {remaining} seconds.",
                    "action_taken": "THROTTLED",
                    "attack_type": "DIR_FUZZ",
                    "outcome": "BLOCKED",
                    "verification_evidence": {
                        "status_code": 429,
                        "retry_after": remaining,
                        "throttle_tier": tier,
                        "perimeter_enforced": True,
                        "verification_status": "VERIFIED"
                    }
                }

        # 1. HTTP Method Whitelist Check
        if method.upper() not in self.config.allowed_methods:
            return {
                "blocked": True,
                "status_code": 405,
                "rule": "DISALLOWED_METHOD",
                "signature": "DIR_FUZZ",
                "severity": "MEDIUM",
                "message": f"HTTP method '{method}' is not permitted by application firewall",
                "metadata": {"method": method, "allowed": list(self.config.allowed_methods)},
                "client_message": "405 Method Not Allowed: Specified HTTP method is not permitted.",
                "action_taken": "BLOCKED",
                "attack_type": "DISALLOWED_METHOD",
                "outcome": "BLOCKED",
                "verification_evidence": {
                    "status_code": 405,
                    "method": method,
                    "perimeter_enforced": True,
                    "verification_status": "VERIFIED"
                }
            }

        # 2. Request Body Size Limit Check
        if content_length and content_length > self.config.max_content_length:
            return {
                "blocked": True,
                "status_code": 413,
                "rule": "REQUEST_SIZE_LIMIT",
                "signature": "DIR_FUZZ",
                "severity": "MEDIUM",
                "message": f"Request body length ({content_length} bytes) exceeds limit ({self.config.max_content_length} bytes)",
                "metadata": {"size": content_length, "max_allowed": self.config.max_content_length},
                "client_message": "413 Payload Too Large: Request body exceeds the maximum permitted size.",
                "action_taken": "BLOCKED",
                "attack_type": "REQUEST_SIZE_LIMIT",
                "outcome": "BLOCKED",
                "verification_evidence": {
                    "status_code": 413,
                    "content_length": content_length,
                    "max_allowed": self.config.max_content_length,
                    "perimeter_enforced": True,
                    "verification_status": "VERIFIED"
                }
            }

        # 3. Request Rate Limiting Check
        if not self.rate_limiter.is_allowed(source_ip):
            return {
                "blocked": True,
                "status_code": 429,
                "rule": "RATE_LIMIT_EXCEEDED",
                "signature": "DIR_FUZZ",
                "severity": "LOW",
                "message": f"Source IP '{source_ip}' exceeded request rate limit ({self.config.rate_limit_rpm} req/min)",
                "metadata": {"source_ip": source_ip, "rate_limit_rpm": self.config.rate_limit_rpm, "retry_after_seconds": 60},
                "client_message": "429 Too Many Requests: Request rate limit exceeded. Please slow down.",
                "action_taken": "THROTTLED",
                "attack_type": "RATE_LIMIT",
                "outcome": "BLOCKED",
                "verification_evidence": {
                    "status_code": 429,
                    "rate_limit_rpm": self.config.rate_limit_rpm,
                    "perimeter_enforced": True,
                    "verification_status": "VERIFIED"
                }
            }

        # 4. Authentication Brute-Force Lockout Check (applies specifically to login attempts)
        if method.upper() == "POST" and path == "/":
            is_locked, remaining = self.brute_force_protector.is_locked_out(source_ip)
            if is_locked:
                tier = self.brute_force_protector.get_tier(source_ip)
                duration = min(
                    self.brute_force_protector.lockout_seconds * (2 ** max(0, tier - 1)),
                    self.brute_force_protector.max_lockout_seconds
                )
                return {
                    "blocked": True,
                    "status_code": 429,
                    "rule": "AUTH_LOCKOUT_ACTIVE",
                    "signature": "BRUTE_FORCE_AUTH",
                    "severity": "HIGH",
                    "message": f"Client IP '{source_ip}' is locked out due to repeated authentication failures ({remaining}s remaining, Tier {tier})",
                    "metadata": {
                        "source_ip": source_ip,
                        "retry_after_seconds": remaining,
                        "lockout_tier": tier,
                        "lockout_duration_seconds": duration,
                        "policy": "progressive_exponential_lockout"
                    },
                    "client_message": f"429 Too Many Requests: IP temporarily locked out due to repeated failed logins. Retry in {remaining} seconds.",
                    "action_taken": "LOCKED_OUT",
                    "attack_type": "BRUTE_FORCE_AUTH",
                    "outcome": "BLOCKED",
                    "verification_evidence": {
                        "status_code": 429,
                        "retry_after": remaining,
                        "lockout_tier": tier,
                        "lockout_duration_seconds": duration,
                        "perimeter_enforced": True,
                        "verification_status": "VERIFIED"
                    }
                }

        # Normalize components for content inspection
        norm_path = self.normalize_string(path)
        norm_query = self.normalize_string(query_string)
        norm_body = self.normalize_string(body)
        target_content = f"{norm_path}?{norm_query} {norm_body}".lower()
        ua = headers.get("User-Agent", "").lower()

        # 5. SQL Injection Inspection
        if "sqlmap" in ua:
            return {
                "blocked": True,
                "status_code": 400,
                "rule": "SQLI_SCANNER_DETECTED",
                "signature": "SQL_INJECTION",
                "severity": "CRITICAL",
                "message": f"Automated SQL injection tool detected in User-Agent targeting {path}",
                "metadata": {"user_agent": ua, "path": path, "scanner": "sqlmap"},
                "client_message": "400 Bad Request: Malicious SQL injection signature detected.",
                "action_taken": "BLOCKED",
                "attack_type": "SQL_INJECTION",
                "outcome": "BLOCKED" if self.config.mode == "BLOCK" else "MONITORED",
                "verification_evidence": {
                    "status_code": 400 if self.config.mode == "BLOCK" else 200,
                    "rule": "SQLI_SCANNER_DETECTED",
                    "scanner": "sqlmap",
                    "perimeter_enforced": (self.config.mode == "BLOCK"),
                    "verification_status": "VERIFIED"
                }
            }
        for pattern in self.SQLI_PATTERNS:
            if pattern.search(target_content):
                return {
                    "blocked": True,
                    "status_code": 400,
                    "rule": "SQLI_PATTERN_DETECTED",
                    "signature": "SQL_INJECTION",
                    "severity": "CRITICAL",
                    "message": f"SQL injection attempt pattern '{pattern.pattern}' detected in request",
                    "metadata": {"pattern": pattern.pattern, "path": path},
                    "client_message": "400 Bad Request: Malicious SQL injection signature detected.",
                    "action_taken": "BLOCKED",
                    "attack_type": "SQL_INJECTION",
                    "outcome": "BLOCKED" if self.config.mode == "BLOCK" else "MONITORED",
                    "verification_evidence": {
                        "status_code": 400 if self.config.mode == "BLOCK" else 200,
                        "rule": "SQLI_PATTERN_DETECTED",
                        "pattern": pattern.pattern,
                        "perimeter_enforced": (self.config.mode == "BLOCK"),
                        "verification_status": "VERIFIED"
                    }
                }

        # 6. Command Injection Inspection
        for pattern in self.CMDI_PATTERNS:
            if pattern.search(target_content):
                return {
                    "blocked": True,
                    "status_code": 400,
                    "rule": "COMMAND_INJECTION_DETECTED",
                    "signature": "COMMAND_INJECTION",
                    "severity": "CRITICAL",
                    "message": f"Command injection attempt pattern '{pattern.pattern}' detected in request",
                    "metadata": {"pattern": pattern.pattern, "path": path},
                    "client_message": "400 Bad Request: Malicious command injection signature detected.",
                    "action_taken": "BLOCKED",
                    "attack_type": "COMMAND_INJECTION",
                    "outcome": "BLOCKED" if self.config.mode == "BLOCK" else "MONITORED",
                    "verification_evidence": {
                        "status_code": 400 if self.config.mode == "BLOCK" else 200,
                        "rule": "COMMAND_INJECTION_DETECTED",
                        "pattern": pattern.pattern,
                        "perimeter_enforced": (self.config.mode == "BLOCK"),
                        "verification_status": "VERIFIED"
                    }
                }

        # 7. Path Traversal Inspection
        for pattern in self.TRAVERSAL_PATTERNS:
            if pattern.search(target_content):
                return {
                    "blocked": True,
                    "status_code": 400,
                    "rule": "PATH_TRAVERSAL_DETECTED",
                    "signature": "PATH_TRAVERSAL",
                    "severity": "HIGH",
                    "message": f"Directory traversal pattern detected targeting {path}",
                    "metadata": {"path": path, "pattern": pattern.pattern},
                    "client_message": "400 Bad Request: Directory traversal pattern detected.",
                    "action_taken": "BLOCKED",
                    "attack_type": "PATH_TRAVERSAL",
                    "outcome": "BLOCKED" if self.config.mode == "BLOCK" else "MONITORED",
                    "verification_evidence": {
                        "status_code": 400 if self.config.mode == "BLOCK" else 200,
                        "rule": "PATH_TRAVERSAL_DETECTED",
                        "pattern": pattern.pattern,
                        "perimeter_enforced": (self.config.mode == "BLOCK"),
                        "verification_status": "VERIFIED"
                    }
                }

        # 8. Cross-Site Scripting (XSS) Inspection
        for pattern in self.XSS_PATTERNS:
            if pattern.search(target_content):
                # Maps to T1059 (Command and Scripting Interpreter) in Defensive SOC
                return {
                    "blocked": True,
                    "status_code": 400,
                    "rule": "XSS_SCRIPT_DETECTED",
                    "signature": "COMMAND_INJECTION",
                    "severity": "HIGH",
                    "message": f"Cross-Site Scripting (XSS) pattern detected targeting {path}",
                    "metadata": {"attack_type": "CROSS_SITE_SCRIPTING", "path": path, "pattern": pattern.pattern},
                    "client_message": "400 Bad Request: Cross-site scripting payload detected.",
                    "action_taken": "BLOCKED",
                    "attack_type": "CROSS_SITE_SCRIPTING",
                    "outcome": "BLOCKED" if self.config.mode == "BLOCK" else "MONITORED",
                    "verification_evidence": {
                        "status_code": 400 if self.config.mode == "BLOCK" else 200,
                        "rule": "XSS_SCRIPT_DETECTED",
                        "pattern": pattern.pattern,
                        "perimeter_enforced": (self.config.mode == "BLOCK"),
                        "verification_status": "VERIFIED"
                    }
                }

        # 9. Reconnaissance Scanners & Sensitive Path Fuzzing
        for tool in self.SCANNER_AGENTS:
            if tool in ua:
                return {
                    "blocked": True,
                    "status_code": 403,
                    "rule": "RECON_SCANNER_USER_AGENT",
                    "signature": "DIR_FUZZ",
                    "severity": "HIGH",
                    "message": f"Reconnaissance scanner detected ({tool}) targeting {path}",
                    "metadata": {"user_agent": ua, "path": path, "scanner": tool},
                    "client_message": "403 Forbidden: Reconnaissance tool detected.",
                    "action_taken": "BLOCKED",
                    "attack_type": "DIR_FUZZ",
                    "outcome": "BLOCKED" if self.config.mode == "BLOCK" else "MONITORED",
                    "verification_evidence": {
                        "status_code": 403 if self.config.mode == "BLOCK" else 200,
                        "rule": "RECON_SCANNER_USER_AGENT",
                        "scanner": tool,
                        "perimeter_enforced": (self.config.mode == "BLOCK"),
                        "verification_status": "VERIFIED"
                    }
                }
        for fpath in self.SENSITIVE_PATHS:
            if fpath in norm_path.lower():
                return {
                    "blocked": True,
                    "status_code": 403,
                    "rule": "SENSITIVE_PATH_PROBE",
                    "signature": "DIR_FUZZ",
                    "severity": "HIGH",
                    "message": f"Sensitive file or administrative path fuzzing detected: {path}",
                    "metadata": {"path": path, "sensitive_path": fpath},
                    "client_message": "403 Forbidden: Access to requested path is restricted.",
                    "action_taken": "BLOCKED",
                    "attack_type": "DIR_FUZZ",
                    "outcome": "BLOCKED" if self.config.mode == "BLOCK" else "MONITORED",
                    "verification_evidence": {
                        "status_code": 403 if self.config.mode == "BLOCK" else 200,
                        "rule": "SENSITIVE_PATH_PROBE",
                        "sensitive_path": fpath,
                        "perimeter_enforced": (self.config.mode == "BLOCK"),
                        "verification_status": "VERIFIED"
                    }
                }

        return None

    def build_client_response(self, detection: Dict[str, Any]) -> Response:
        """Construct safe, generic client-facing HTTP error response."""
        status_code = detection.get("status_code", 400)
        client_msg = detection.get("client_message", "Request rejected by application security policy.")
        rule = detection.get("rule", "SECURITY_POLICY")

        html_body = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Request Blocked</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, sans-serif;
            background: #0f172a;
            color: #f8fafc;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
        }}
        .waf-card {{
            background: #1e293b;
            border: 1px solid #334155;
            border-radius: 12px;
            padding: 32px 40px;
            max-width: 480px;
            text-align: center;
            box-shadow: 0 10px 25px rgba(0, 0, 0, 0.5);
        }}
        .waf-badge {{
            display: inline-block;
            background: #ef4444;
            color: #ffffff;
            font-size: 0.75rem;
            font-weight: 700;
            padding: 4px 10px;
            border-radius: 9999px;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            margin-bottom: 16px;
        }}
        h1 {{
            margin: 0 0 12px;
            font-size: 1.35rem;
            color: #f8fafc;
        }}
        p {{
            margin: 0 0 20px;
            font-size: 0.9rem;
            color: #94a3b8;
            line-height: 1.5;
        }}
        .waf-footer {{
            font-size: 0.75rem;
            color: #64748b;
            border-top: 1px solid #334155;
            padding-top: 14px;
        }}
    </style>
</head>
<body>
    <div class="waf-card">
        <div class="waf-badge">WAF Protection Active</div>
        <h1>Request Rejected</h1>
        <p>{client_msg}</p>
        <div class="waf-footer">Protected Enterprise Web Application · Security Event Recorded</div>
    </div>
</body>
</html>
"""
        resp = Response(html_body, status=status_code, mimetype="text/html")
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        if status_code == 429 and "retry_after_seconds" in detection.get("metadata", {}):
            resp.headers["Retry-After"] = str(detection["metadata"]["retry_after_seconds"])
        return resp
