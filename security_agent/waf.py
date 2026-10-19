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

        # Authentication brute-force lockout policy
        self.auth_lockout_threshold: int = int(os.getenv("WAF_AUTH_LOCKOUT_THRESHOLD", "3"))
        self.auth_lockout_seconds: int = int(os.getenv("WAF_AUTH_LOCKOUT_SECONDS", "60"))
        self.auth_decay_seconds: int = int(os.getenv("WAF_AUTH_DECAY_SECONDS", "300"))


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
    """Tracks authentication failures and applies temporary client IP lockout."""

    def __init__(self, threshold: int = 3, lockout_seconds: int = 60, decay_seconds: int = 300):
        self.threshold = threshold
        self.lockout_seconds = lockout_seconds
        self.decay_seconds = decay_seconds
        self.failures: Dict[str, List[float]] = {}
        self.lockouts: Dict[str, float] = {}  # ip -> lockout_until
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

    def record_failure(self, ip: str) -> Tuple[int, bool]:
        """Record an auth failure. Returns (current_count, is_now_locked_out)."""
        now = time.time()
        with self._lock:
            recent = [t for t in self.failures.get(ip, []) if now - t < self.decay_seconds]
            recent.append(now)
            self.failures[ip] = recent
            count = len(recent)

            if count >= self.threshold:
                self.lockouts[ip] = now + self.lockout_seconds
                return count, True
            return count, False

    def record_success(self, ip: str):
        """Clear failure history upon verified successful authentication."""
        with self._lock:
            self.failures.pop(ip, None)
            self.lockouts.pop(ip, None)


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
    SENSITIVE_PATHS = ["/.env", "/wp-admin", "/phpmyadmin", "/.git", "/config.php", "/backup.zip", "/admin.php"]

    def __init__(self, config: Optional[WAFConfig] = None):
        self.config = config or WAFConfig()
        self.rate_limiter = RateLimiter(self.config.rate_limit_rpm)
        self.brute_force_protector = BruteForceProtector(
            threshold=self.config.auth_lockout_threshold,
            lockout_seconds=self.config.auth_lockout_seconds,
            decay_seconds=self.config.auth_decay_seconds
        )

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
        """
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
                "client_message": "405 Method Not Allowed: Specified HTTP method is not permitted."
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
                "client_message": "413 Payload Too Large: Request body exceeds the maximum permitted size."
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
                "metadata": {"source_ip": source_ip, "rate_limit_rpm": self.config.rate_limit_rpm},
                "client_message": "429 Too Many Requests: Request rate limit exceeded. Please slow down."
            }

        # 4. Authentication Brute-Force Lockout Check (applies specifically to login attempts)
        if method.upper() == "POST" and path == "/":
            is_locked, remaining = self.brute_force_protector.is_locked_out(source_ip)
            if is_locked:
                return {
                    "blocked": True,
                    "status_code": 429,
                    "rule": "AUTH_LOCKOUT_ACTIVE",
                    "signature": "BRUTE_FORCE_AUTH",
                    "severity": "HIGH",
                    "message": f"Client IP '{source_ip}' is locked out due to repeated authentication failures ({remaining}s remaining)",
                    "metadata": {"source_ip": source_ip, "retry_after_seconds": remaining},
                    "client_message": f"429 Too Many Requests: IP temporarily locked out due to repeated failed logins. Retry in {remaining} seconds."
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
                "metadata": {"user_agent": ua, "path": path},
                "client_message": "400 Bad Request: Malicious SQL injection signature detected."
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
                    "client_message": "400 Bad Request: Malicious SQL injection signature detected."
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
                    "client_message": "400 Bad Request: Malicious command injection signature detected."
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
                    "metadata": {"path": path},
                    "client_message": "400 Bad Request: Directory traversal pattern detected."
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
                    "metadata": {"attack_type": "CROSS_SITE_SCRIPTING", "path": path},
                    "client_message": "400 Bad Request: Cross-site scripting payload detected."
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
                    "metadata": {"user_agent": ua, "path": path},
                    "client_message": "403 Forbidden: Reconnaissance tool detected."
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
                    "metadata": {"path": path},
                    "client_message": "403 Forbidden: Access to requested path is restricted."
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
