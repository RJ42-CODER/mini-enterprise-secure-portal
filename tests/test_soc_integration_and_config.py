"""
Comprehensive integration and unit test suite for Secure Portal:
- Configuration loading, fallback parsing, and multi-variable startup validation
- Token preservation and SOC_API_KEY / SOC_AGENT_TOKEN alias synchronization
- Event payload generation and SOC Ingestion API schema conformance
- Authorization headers and request headers
- Authentic client IP extraction across Nginx reverse proxy headers
- Resilient connection failure handling and local disk buffering
- Portal stability when SOC dashboard port 8443 is unreachable
"""

import os
import json
import time
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

from security_agent.config import load_portal_env, validate_portal_config, get_client_ip
from security_agent.alert_client import AlertClient
from security_agent.detector import ServerDetector
from app import app


# ==============================================================================
# 1. Configuration Loading & Startup Validation Tests
# ==============================================================================

def test_validate_portal_config_success():
    """Verify validate_portal_config succeeds with expected keys and does not expose secrets."""
    with patch.dict(os.environ, {
        "CN_SERVER_IP": "192.168.31.91",
        "SOC_URL": "http://192.168.31.73:8443",
        "SOC_API_KEY": "super_secret_token_12345",
        "PORT": "5000",
        "FLASK_HOST": "127.0.0.1"
    }):
        cfg = validate_portal_config()
        assert cfg["CN_SERVER_IP"] == "192.168.31.91"
        assert cfg["SOC_URL"] == "http://192.168.31.73:8443"
        assert cfg["PORT"] == 5000
        assert cfg["FLASK_HOST"] == "127.0.0.1"
        assert cfg["SOC_AUTH_CONFIGURED"] is True
        # Ensure secret value is never returned in config dictionary
        assert "super_secret_token_12345" not in str(cfg)


def test_validate_portal_config_reports_all_missing_settings():
    """Verify that multiple missing settings are reported together in a single clear error."""
    with patch.dict(os.environ, {}, clear=True):
        with pytest.raises(ValueError) as excinfo:
            validate_portal_config()
        err_msg = str(excinfo.value)
        assert "CN_SERVER_IP" in err_msg
        assert "SOC_URL" in err_msg
        assert "SOC_API_KEY or SOC_AGENT_TOKEN" in err_msg


def test_validate_portal_config_invalid_url_scheme():
    """Verify invalid SOC_URL scheme raises clear ValueError."""
    with patch.dict(os.environ, {
        "CN_SERVER_IP": "192.168.31.91",
        "SOC_URL": "ftp://192.168.31.73:8443",
        "SOC_API_KEY": "test_token"
    }):
        with pytest.raises(ValueError, match="Must start with http:// or https://"):
            validate_portal_config()


def test_validate_portal_config_invalid_port():
    """Verify non-integer PORT raises ValueError."""
    with patch.dict(os.environ, {
        "CN_SERVER_IP": "192.168.31.91",
        "SOC_URL": "http://192.168.31.73:8443",
        "SOC_API_KEY": "test_token",
        "PORT": "not_a_number"
    }):
        with pytest.raises(ValueError, match="valid integer port number"):
            validate_portal_config()


def test_soc_token_alias_synchronization(tmp_path):
    """Verify that load_portal_env synchronizes SOC_API_KEY and SOC_AGENT_TOKEN."""
    test_env = tmp_path / ".env"
    test_env.write_text("SOC_API_KEY=test_token_sync_val\n", encoding="utf-8")

    with patch.dict(os.environ, {}, clear=True):
        loaded = load_portal_env(test_env)
        assert loaded is True
        assert os.environ.get("SOC_API_KEY") == "test_token_sync_val"
        assert os.environ.get("SOC_AGENT_TOKEN") == "test_token_sync_val"


def test_load_portal_env_fallback_parser_without_dotenv(tmp_path):
    """Verify manual fallback parser works when python-dotenv is not used."""
    test_env = tmp_path / ".env"
    test_env.write_text(
        "# Comment line\n"
        "CN_SERVER_IP=192.168.31.91\n"
        "SOC_URL=http://192.168.31.73:8443\n"
        "SOC_API_KEY='token_with_quotes'\n",
        encoding="utf-8"
    )

    with patch.dict(os.environ, {}, clear=True):
        with patch.dict("sys.modules", {"dotenv": None}):
            loaded = load_portal_env(test_env)
            assert loaded is True
            assert os.environ.get("CN_SERVER_IP") == "192.168.31.91"
            assert os.environ.get("SOC_URL") == "http://192.168.31.73:8443"
            assert os.environ.get("SOC_API_KEY") == "token_with_quotes"


# ==============================================================================
# 2. SOC Telemetry Event Payload & Contract Conformance Tests
# ==============================================================================

def test_soc_payload_schema_and_headers(tmp_path):
    """Verify payload structure, Authorization Bearer header, and User-Agent."""
    client = AlertClient(
        soc_url="http://192.168.31.73:8443",
        api_key="secret_bearer_token",
        spool_dir=str(tmp_path)
    )
    client._flush_spool_quietly = MagicMock()

    with patch("requests.post") as mock_post:
        mock_post.return_value.status_code = 202
        mock_post.return_value.json.return_value = {"status": "accepted"}

        payload = {
            "event_id": "EVT-TEST-001",
            "source_ip": "192.168.31.200",
            "destination_ip": "192.168.31.91",
            "destination_port": 5000,
            "signature": "SQL_INJECTION",
            "severity": "CRITICAL",
            "message": "SQL injection test pattern",
            "metadata": {"query": "id=1' or '1'='1"}
        }

        success, res = client.send_event(payload)
        assert success is True
        mock_post.assert_called_once()

        # Check request headers
        headers_used = mock_post.call_args[1]["headers"]
        assert headers_used["Authorization"] == "Bearer secret_bearer_token"
        assert headers_used["Content-Type"] == "application/json"
        assert "HP-Victus-Security-Agent" in headers_used["User-Agent"]

        # Check endpoint
        assert mock_post.call_args[0][0] == "http://192.168.31.73:8443/api/events"

        # Check outgoing payload schema
        sent_json = mock_post.call_args[1]["json"]
        assert sent_json["source_ip"] == "192.168.31.200"
        assert sent_json["signature"] == "SQL_INJECTION"
        assert sent_json["severity"] == "CRITICAL"


def test_port_scan_info_severity_normalized_to_low(tmp_path):
    """
    Verify that INFO severity (e.g. from network port canary probes)
    is normalized to LOW so the SOC Ingestion API schema accepts it.
    """
    client = AlertClient(
        soc_url="http://192.168.31.73:8443",
        api_key="test_token",
        spool_dir=str(tmp_path)
    )
    client._flush_spool_quietly = MagicMock()

    with patch("requests.post") as mock_post:
        mock_post.return_value.status_code = 202
        mock_post.return_value.json.return_value = {"status": "accepted"}

        payload = {
            "event_id": "EVT-SCAN-01",
            "source_ip": "192.168.31.200",
            "destination_port": 22,
            "signature": "PORT_SCAN",
            "severity": "INFO",
            "message": "Port probe detected"
        }

        success, _ = client.send_event(payload)
        assert success is True
        sent_json = mock_post.call_args[1]["json"]
        # Must be mapped to LOW to satisfy SOC schema ('low', 'medium', 'high', 'critical')
        assert sent_json["severity"] == "LOW"


def test_soc_events_endpoint_override_respected(tmp_path):
    """Verify custom SOC_EVENTS_ENDPOINT override is respected."""
    with patch.dict(os.environ, {"SOC_EVENTS_ENDPOINT": "http://192.168.31.73:8443/custom/ingest"}):
        client = AlertClient(
            soc_url="http://192.168.31.73:8443",
            api_key="test_token",
            spool_dir=str(tmp_path)
        )
        assert client.endpoint == "http://192.168.31.73:8443/custom/ingest"


# ==============================================================================
# 3. Authentic Client IP Resolution (Nginx Reverse Proxy)
# ==============================================================================

def test_get_client_ip_from_x_forwarded_for():
    """Verify client IP extraction from X-Forwarded-For header."""
    mock_req = MagicMock()
    mock_req.headers = {"X-Forwarded-For": "192.168.31.200, 127.0.0.1"}
    mock_req.remote_addr = "127.0.0.1"

    ip = get_client_ip(mock_req)
    assert ip == "192.168.31.200"


def test_get_client_ip_from_x_real_ip():
    """Verify client IP extraction from X-Real-IP header."""
    mock_req = MagicMock()
    mock_req.headers = {"X-Real-IP": "192.168.31.200"}
    mock_req.remote_addr = "127.0.0.1"

    ip = get_client_ip(mock_req)
    assert ip == "192.168.31.200"


def test_get_client_ip_fallback_to_remote_addr():
    """Verify client IP falls back to remote_addr when no proxy headers exist."""
    mock_req = MagicMock()
    mock_req.headers = {}
    mock_req.remote_addr = "10.0.0.50"

    ip = get_client_ip(mock_req)
    assert ip == "10.0.0.50"


def test_reverse_proxy_client_ip_retained_in_waf_event():
    """Verify that requests forwarded through Nginx pass authentic IP to detector."""
    client = app.test_client()
    with patch("app.detector") as mock_det:
        client.get(
            "/?id=1%20UNION%20SELECT%201",
            headers={"X-Forwarded-For": "192.168.31.200, 127.0.0.1"}
        )
        mock_det.inspect_http_request.assert_called_once()
        kwargs = mock_det.inspect_http_request.call_args[1]
        assert kwargs["source_ip"] == "192.168.31.200"


# ==============================================================================
# 4. Connection Failures & Offline Spooling Tests
# ==============================================================================

def test_soc_unreachable_returns_clear_error_and_spools(tmp_path):
    """Verify connection failure provides clear diagnostic message and buffers locally."""
    import requests
    client = AlertClient(
        soc_url="http://192.168.31.73:8443",
        api_key="test_token",
        spool_dir=str(tmp_path)
    )
    client._flush_spool_quietly = MagicMock()

    with patch("requests.post", side_effect=requests.exceptions.ConnectionError("Connection refused")):
        payload = {
            "event_id": "EVT-OFFLINE-01",
            "source_ip": "192.168.31.200",
            "signature": "PORT_SCAN",
            "severity": "LOW"
        }
        success, res = client.send_event(payload)
        assert success is False
        assert res["error"] == "ConnectionError"
        assert "unreachable" in res["detail"].lower()
        assert res["buffered"] is True
        assert client.spool_file.exists()
        spooled = client.spool_file.read_text(encoding="utf-8")
        assert "EVT-OFFLINE-01" in spooled


def test_portal_remains_available_when_soc_unreachable(tmp_path):
    """Verify the portal serves login pages normally even if SOC API (port 8443) is down."""
    import requests
    client = app.test_client()
    from app import detector

    with patch("requests.post", side_effect=requests.exceptions.ConnectionError("Connection refused")):
        # Normal GET request
        resp = client.get("/")
        assert resp.status_code == 200
        assert b"Secure Portal" in resp.data

        # Legitimate login attempt
        resp_login = client.post("/", data={"username": "admin", "password": "wrongpassword"})
        assert resp_login.status_code == 200
        assert b"Invalid username or password" in resp_login.data


def test_detector_heartbeat_payload():
    """Verify heartbeat payload has non-attack signature and valid destination IP."""
    with patch("security_agent.detector.AlertClient") as mock_client_cls:
        mock_client = mock_client_cls.return_value
        mock_client.send_event.return_value = (True, {"status": "accepted"})
        detector = ServerDetector(soc_url="http://192.168.31.73:8443", api_key="k", port=5000)

        hb = detector.record_heartbeat()
        assert hb["signature"] == "HEARTBEAT"
        assert hb["event_type"] == "HEARTBEAT"
        assert hb["source_ip"] == "192.168.31.91"
        assert hb["destination_port"] == 5000


def test_env_new_security_variables_loaded_and_parsed():
    """Verify that new rate-anomaly, proxy, and ML settings are loaded and typed correctly from .env."""
    from security_agent.config import load_portal_env, get_trusted_proxies
    from security_agent.rate_anomaly_detector import RateAnomalyConfig
    from security_agent.ml_detector import MLAnomalyDetector
    from security_agent.waf import WAFConfig

    loaded = load_portal_env()
    assert loaded is True

    rac = RateAnomalyConfig()
    assert isinstance(rac.enabled, bool)
    assert isinstance(rac.window_seconds, float)
    assert isinstance(rac.threshold, int)
    assert isinstance(rac.burst_window_seconds, float)
    assert isinstance(rac.burst_threshold, int)
    assert isinstance(rac.cooldown_seconds, float)
    assert isinstance(rac.max_tracked_identities, int)
    assert isinstance(rac.excluded_paths, set)
    assert "/health" in rac.excluded_paths

    proxies = get_trusted_proxies()
    assert isinstance(proxies, set)
    assert "127.0.0.1" in proxies

    mld = MLAnomalyDetector()
    assert isinstance(mld.enabled, bool)

    waf = WAFConfig()
    assert isinstance(waf.dir_fuzz_threshold, int)
    assert isinstance(waf.auth_lockout_max_seconds, int)
    assert isinstance(waf.rate_limit_burst, int)


def test_env_rate_anomaly_defaults_when_absent():
    """Verify safe fallback defaults when rate-anomaly variables are absent."""
    from security_agent.rate_anomaly_detector import RateAnomalyConfig

    with patch.dict(os.environ, {}, clear=True):
        rac = RateAnomalyConfig()
        assert rac.enabled is True
        assert rac.window_seconds == 10.0
        assert rac.threshold == 15
        assert rac.burst_window_seconds == 2.0
        assert rac.burst_threshold == 8
        assert rac.cooldown_seconds == 30.0
        assert rac.max_tracked_identities == 2000
        assert "/health" in rac.excluded_paths
