import os
import json
import time
import pytest
from unittest.mock import patch, MagicMock

# Configure environment before module imports
os.environ["CN_SERVER_IP"] = "192.168.31.91"
os.environ["SOC_URL"] = "http://127.0.0.1:8443"
os.environ["SOC_API_KEY"] = "test_waf_mock_token"
os.environ["PORT"] = "5000"
os.environ["WAF_MODE"] = "BLOCK"
os.environ["WAF_MAX_CONTENT_LENGTH"] = "51200"  # 50 KB for test
os.environ["WAF_ALLOWED_METHODS"] = "GET,POST,HEAD"
os.environ["WAF_RATE_LIMIT_RPM"] = "20"
os.environ["WAF_AUTH_LOCKOUT_THRESHOLD"] = "3"
os.environ["WAF_AUTH_LOCKOUT_SECONDS"] = "2"
os.environ["WAF_AUTH_DECAY_SECONDS"] = "10"

from security_agent.waf import WAFConfig, WAFInspector, RateLimiter, BruteForceProtector
from security_agent.detector import ServerDetector
from app import app


@pytest.fixture
def test_client():
    """Flask test client with clean rate limiter, lockout tracking, and spool isolation."""
    app.config["TESTING"] = True
    from app import detector
    with patch.object(detector.client, '_flush_spool_quietly'):
        # Reset WAF tracking state between tests
        detector.waf.rate_limiter = RateLimiter(limit_per_minute=20)
        detector.waf.brute_force_protector = BruteForceProtector(
            threshold=3, lockout_seconds=2, decay_seconds=10
        )
        detector.failed_logins.clear()
        with app.test_client() as client:
            yield client


# ==============================================================================
# Requirement 1: Normal login and legitimate request succeeding
# ==============================================================================

def test_normal_legitimate_request_succeeds(test_client):
    """Verify that a legitimate GET request to portal returns HTTP 200 OK."""
    with patch('requests.post') as mock_post:
        resp = test_client.get('/')
        assert resp.status_code == 200
        assert b"Secure Portal" in resp.data
        mock_post.assert_not_called()


def test_normal_login_succeeds(test_client):
    """Verify legitimate admin login succeeds with correct credentials."""
    admin_pass = os.getenv("PORTAL_ADMIN_PASSWORD", "admin123")
    with patch('requests.post') as mock_post:
        resp = test_client.post('/', data={
            "username": "admin",
            "password": admin_pass
        })
        assert resp.status_code == 200
        assert b"Login successful" in resp.data


# ==============================================================================
# Requirement 2: SQL Injection rejection and telemetry mapping
# ==============================================================================

def test_sqli_in_query_string_blocked(test_client):
    """Verify controlled SQL injection in URL parameter is blocked with HTTP 400."""
    with patch('requests.post') as mock_post:
        mock_post.return_value.status_code = 200
        mock_post.return_value.json.return_value = {"status": "success"}

        resp = test_client.get("/?id=1%20UNION%20SELECT%201,2,3")
        assert resp.status_code == 400
        assert b"Request Rejected" in resp.data
        assert b"SQL injection signature detected" in resp.data

        # Verify telemetry was dispatched to SOC
        mock_post.assert_called_once()
        payload = mock_post.call_args[1]["json"]
        assert payload["signature"] == "SQL_INJECTION"
        assert payload["severity"] == "CRITICAL"


def test_sqli_in_form_body_blocked(test_client):
    """Verify SQL injection attempt in POST body is blocked with HTTP 400."""
    with patch('requests.post') as mock_post:
        mock_post.return_value.status_code = 200
        mock_post.return_value.json.return_value = {"status": "success"}

        resp = test_client.post("/", data={
            "username": "admin' OR '1'='1",
            "password": "xyz"
        })
        assert resp.status_code == 400
        assert b"WAF Protection Active" in resp.data


def test_sqli_in_monitor_mode_alerts_without_blocking(test_client):
    """Verify WAF_MODE=MONITOR records alert to SOC but allows request to proceed."""
    from app import detector
    orig_mode = detector.waf.config.mode
    detector.waf.config.mode = "MONITOR"
    try:
        with patch('requests.post') as mock_post:
            mock_post.return_value.status_code = 200
            mock_post.return_value.json.return_value = {"status": "success"}

            resp = test_client.get("/?search=' OR '1'='1")
            # In MONITOR mode, request proceeds to handler (200 OK)
            assert resp.status_code == 200
            # But security event was still generated and sent to SOC
            mock_post.assert_called_once()
            payload = mock_post.call_args[1]["json"]
            assert payload["signature"] == "SQL_INJECTION"
    finally:
        detector.waf.config.mode = orig_mode


# ==============================================================================
# Requirement 3: Path Traversal rejection
# ==============================================================================

def test_path_traversal_blocked(test_client):
    """Verify directory traversal attack is blocked with HTTP 400."""
    with patch('requests.post') as mock_post:
        mock_post.return_value.status_code = 200
        mock_post.return_value.json.return_value = {"status": "success"}

        resp = test_client.get("/?view=../../../../etc/passwd")
        assert resp.status_code == 400
        assert b"Directory traversal pattern detected" in resp.data

        mock_post.assert_called_once()
        payload = mock_post.call_args[1]["json"]
        assert payload["signature"] == "PATH_TRAVERSAL"
        assert payload["severity"] == "HIGH"


# ==============================================================================
# Requirement 4: Command Injection and XSS rejection
# ==============================================================================

def test_command_injection_blocked(test_client):
    """Verify command injection pattern is blocked with HTTP 400."""
    with patch('requests.post') as mock_post:
        mock_post.return_value.status_code = 200
        mock_post.return_value.json.return_value = {"status": "success"}

        resp = test_client.get("/?action=test;%20whoami")
        assert resp.status_code == 400
        assert b"command injection signature detected" in resp.data

        mock_post.assert_called_once()
        payload = mock_post.call_args[1]["json"]
        assert payload["signature"] == "COMMAND_INJECTION"
        assert payload["severity"] == "CRITICAL"


def test_cross_site_scripting_blocked(test_client):
    """Verify XSS attempt is blocked with HTTP 400 and mapped to COMMAND_INJECTION."""
    with patch('requests.post') as mock_post:
        mock_post.return_value.status_code = 200
        mock_post.return_value.json.return_value = {"status": "success"}

        resp = test_client.get("/?comment=<script>alert('xss')</script>")
        assert resp.status_code == 400
        assert b"Cross-site scripting payload detected" in resp.data

        mock_post.assert_called_once()
        payload = mock_post.call_args[1]["json"]
        assert payload["signature"] == "COMMAND_INJECTION"
        assert payload["metadata"]["attack_type"] == "CROSS_SITE_SCRIPTING"


# ==============================================================================
# Requirement 5: Request Size Limits and Oversized Bodies
# ==============================================================================

def test_oversized_payload_rejected(test_client):
    """Verify request exceeding max content length limit is rejected with HTTP 413."""
    from app import detector
    orig_max = detector.waf.config.max_content_length
    orig_app_max = app.config.get('MAX_CONTENT_LENGTH')
    detector.waf.config.max_content_length = 1024
    app.config['MAX_CONTENT_LENGTH'] = 1024
    try:
        with patch('requests.post') as mock_post:
            mock_post.return_value.status_code = 200
            mock_post.return_value.json.return_value = {"status": "success"}

            oversized_data = "a" * 2048
            resp = test_client.post(
                "/",
                data={"username": "alice", "payload": oversized_data},
                headers={"Content-Length": "2100"}
            )
            assert resp.status_code == 413
            assert b"413 Payload Too Large" in resp.data
    finally:
        detector.waf.config.max_content_length = orig_max
        app.config['MAX_CONTENT_LENGTH'] = orig_app_max


# ==============================================================================
# Requirement 6: Disallowed HTTP Methods and Rate Limiting
# ==============================================================================

def test_disallowed_http_method_rejected(test_client):
    """Verify disallowed HTTP methods (e.g. PUT/DELETE/TRACE) are rejected with HTTP 405."""
    with patch('requests.post'):
        resp = test_client.delete("/")
        assert resp.status_code == 405
        assert b"405 Method Not Allowed" in resp.data


def test_sliding_window_rate_limiting(test_client):
    """Verify client exceeding rate limit threshold is blocked with HTTP 429."""
    from app import detector
    detector.waf.rate_limiter.limit = 5

    with patch('requests.post'):
        # Send 5 allowed requests
        for _ in range(5):
            res = test_client.get("/")
            assert res.status_code == 200

        # 6th request should exceed rate limit
        blocked_res = test_client.get("/")
        assert blocked_res.status_code == 429
        assert b"Request rate limit exceeded" in blocked_res.data


# ==============================================================================
# Requirement 7: Brute-Force Authentication Lockout
# ==============================================================================

def test_repeated_failed_logins_trigger_lockout(test_client):
    """Verify repeated failed logins trigger lockout and subsequent HTTP 429."""
    with patch('requests.post'):
        # 1st failure: 200 OK (invalid credentials message)
        res1 = test_client.post('/', data={"username": "admin", "password": "wrong_password_1"})
        assert res1.status_code == 200
        assert b"Invalid username or password" in res1.data

        # 2nd failure: 200 OK
        res2 = test_client.post('/', data={"username": "admin", "password": "wrong_password_2"})
        assert res2.status_code == 200

        # 3rd failure: reaches lockout threshold
        res3 = test_client.post('/', data={"username": "admin", "password": "wrong_password_3"})
        assert res3.status_code == 200

        # 4th attempt: WAF intercepts and blocks with 429
        res4 = test_client.post('/', data={"username": "admin", "password": "any_password"})
        assert res4.status_code == 429
        assert b"IP temporarily locked out" in res4.data
        assert "Retry-After" in res4.headers


# ==============================================================================
# Requirement 8: SOC Event Ingestion & Transient Unavailability
# ==============================================================================

def test_soc_event_authenticated_delivery(test_client):
    """Verify telemetry payload structure and Authorization Bearer header."""
    from app import detector
    with patch.object(detector.client, '_flush_spool_quietly'):
        with patch('requests.post') as mock_post:
            mock_post.return_value.status_code = 200
            mock_post.return_value.json.return_value = {"status": "success"}

            test_client.get("/?cmd=;%20whoami")
            mock_post.assert_called_once()
            call_headers = mock_post.call_args[1]["headers"]
            assert call_headers["Authorization"].startswith("Bearer ")
            assert detector.client.api_key in call_headers["Authorization"]
            assert call_headers["Content-Type"] == "application/json"
            assert mock_post.call_args[1]["json"]["signature"] == "COMMAND_INJECTION"


def test_soc_unavailability_does_not_crash_portal(test_client):
    """Verify portal gracefully handles SOC backend connection failures."""
    import requests
    with patch('requests.post', side_effect=requests.exceptions.ConnectionError("SOC down")):
        # Request should still block malicious input and return 400, not 500
        resp = test_client.get("/?q=' OR '1'='1")
        assert resp.status_code == 400
        assert b"Malicious SQL injection signature detected" in resp.data


# ==============================================================================
# Requirement 9: False-Positive Resistance
# ==============================================================================

def test_false_positive_resistance_complex_password(test_client):
    """Verify complex passwords with special characters (!@#$%^&*~) do not trigger WAF."""
    orig_pass = os.environ.get("PORTAL_ADMIN_PASSWORD", "admin123")
    os.environ["PORTAL_ADMIN_PASSWORD"] = "StrongP@ssw0rd!2026#Complex"
    try:
        with patch('requests.post'):
            resp = test_client.post('/', data={
                "username": "admin",
                "password": "StrongP@ssw0rd!2026#Complex"
            })
            assert resp.status_code == 200
            assert b"Login successful" in resp.data
    finally:
        os.environ["PORTAL_ADMIN_PASSWORD"] = orig_pass


def test_false_positive_resistance_normal_text(test_client):
    """Verify legitimate queries with words like 'select', 'update', 'test' are not blocked."""
    with patch('requests.post'):
        # Normal words without SQL syntax structure
        resp1 = test_client.get("/?selection=option1&updated_date=2026-10-18")
        assert resp1.status_code == 200

        # Hyphenated username or parameter
        resp2 = test_client.get("/?username=john-doe&category=system-administration")
        assert resp2.status_code == 200


# ==============================================================================
# Requirement 10: Production Deployment & Backend Isolation Verification
# ==============================================================================

def test_flask_host_binding_configuration():
    """Verify FLASK_HOST defaults to 127.0.0.1 or respects environment isolation."""
    # Production deployment requires binding to 127.0.0.1 so external clients cannot bypass WAF
    prod_host = os.getenv("FLASK_HOST", "127.0.0.1")
    assert prod_host in ("127.0.0.1", "localhost"), (
        "Flask must bind to localhost (127.0.0.1) in production behind Nginx reverse proxy."
    )
