import os
import json
import time
import pytest
from unittest.mock import patch, MagicMock

# Set required test env vars before imports
os.environ["CN_SERVER_IP"] = "192.168.31.91"
os.environ["SOC_URL"] = "http://127.0.0.1:8443"
os.environ["SOC_API_KEY"] = "mock_test_token"
os.environ["PORT"] = "5000"
os.environ["PORTAL_ADMIN_PASSWORD"] = "admin123"

from security_agent.alert_client import AlertClient
from security_agent.detector import ServerDetector
from security_agent.event_logger import EventLogger
from app import app


# ---------------------------------------------------------------------------
# 1. Environment & Configuration Tests
# ---------------------------------------------------------------------------

def test_missing_token_raises_value_error():
    """Verify AlertClient requires explicit token and has no hardcoded fallback."""
    orig_key = os.environ.pop("SOC_API_KEY", None)
    orig_token = os.environ.pop("SOC_AGENT_TOKEN", None)
    try:
        with pytest.raises(ValueError, match="SOC authentication token is not configured"):
            AlertClient(soc_url="http://127.0.0.1:5050")
    finally:
        if orig_key:
            os.environ["SOC_API_KEY"] = orig_key
        if orig_token:
            os.environ["SOC_AGENT_TOKEN"] = orig_token


def test_soc_agent_token_env_supported():
    """Verify SOC_AGENT_TOKEN alternative environment variable is supported."""
    orig_key = os.environ.pop("SOC_API_KEY", None)
    orig_token = os.environ.get("SOC_AGENT_TOKEN")
    os.environ["SOC_AGENT_TOKEN"] = "alt_agent_token_value"
    try:
        client = AlertClient(soc_url="http://127.0.0.1:5050")
        assert client.api_key == "alt_agent_token_value"
    finally:
        if orig_key:
            os.environ["SOC_API_KEY"] = orig_key
        if orig_token:
            os.environ["SOC_AGENT_TOKEN"] = orig_token
        else:
            os.environ.pop("SOC_AGENT_TOKEN", None)


# ---------------------------------------------------------------------------
# 2. Telemetry Signature Mapping Tests
# ---------------------------------------------------------------------------

def test_sql_injection_signature_mapping():
    """Verify SQL injection maps to registered SQL_INJECTION signature with CRITICAL severity."""
    with patch('security_agent.detector.AlertClient') as mock_client_cls:
        mock_client = mock_client_cls.return_value
        mock_client.send_event.return_value = (True, {})
        detector = ServerDetector(soc_url="http://test", api_key="k", port=5000)

        # In query string
        event = detector.inspect_http_request(
            source_ip="192.168.1.50",
            path="/login",
            method="GET",
            headers={},
            query_string="user=' or '1'='1"
        )
        assert event is not None
        assert event["signature"] == "SQL_INJECTION"
        assert event["alert_type"] == "SQL_INJECTION"
        assert event["severity"] == "CRITICAL"
        assert event["destination_port"] == 5000

        # In form body
        event_body = detector.inspect_http_request(
            source_ip="192.168.1.50",
            path="/",
            method="POST",
            headers={},
            query_string="",
            body="username=admin&password=union select 1,2"
        )
        assert event_body is not None
        assert event_body["signature"] == "SQL_INJECTION"


def test_command_injection_signature_mapping():
    """Verify command injection maps to registered COMMAND_INJECTION signature."""
    with patch('security_agent.detector.AlertClient') as mock_client_cls:
        mock_client = mock_client_cls.return_value
        mock_client.send_event.return_value = (True, {})
        detector = ServerDetector(soc_url="http://test", api_key="k", port=5000)

        event = detector.inspect_http_request(
            source_ip="10.0.0.5",
            path="/test",
            method="GET",
            headers={},
            query_string="cmd=; whoami"
        )
        assert event is not None
        assert event["signature"] == "COMMAND_INJECTION"
        assert event["alert_type"] == "COMMAND_INJECTION"
        assert event["severity"] == "CRITICAL"


def test_path_traversal_signature_mapping():
    """Verify directory traversal maps to registered PATH_TRAVERSAL signature."""
    with patch('security_agent.detector.AlertClient') as mock_client_cls:
        mock_client = mock_client_cls.return_value
        mock_client.send_event.return_value = (True, {})
        detector = ServerDetector(soc_url="http://test", api_key="k", port=5000)

        event = detector.inspect_http_request(
            source_ip="10.0.0.5",
            path="/download",
            method="GET",
            headers={},
            query_string="file=../../etc/passwd"
        )
        assert event is not None
        assert event["signature"] == "PATH_TRAVERSAL"
        assert event["severity"] == "HIGH"


def test_dir_fuzz_signature_mapping():
    """Verify reconnaissance scanners and path probes map to registered DIR_FUZZ signature."""
    with patch('security_agent.detector.AlertClient') as mock_client_cls:
        mock_client = mock_client_cls.return_value
        mock_client.send_event.return_value = (True, {})
        detector = ServerDetector(soc_url="http://test", api_key="k", port=5000)

        # Via User-Agent
        event_ua = detector.inspect_http_request(
            source_ip="10.0.0.5",
            path="/",
            method="GET",
            headers={"User-Agent": "Mozilla/5.0 Nikto/2.1.6"},
            query_string=""
        )
        assert event_ua is not None
        assert event_ua["signature"] == "DIR_FUZZ"

        # Via sensitive path fuzzing
        event_path = detector.inspect_http_request(
            source_ip="10.0.0.5",
            path="/.env",
            method="GET",
            headers={"User-Agent": "curl/7.68.0"},
            query_string=""
        )
        assert event_path is not None
        assert event_path["signature"] == "DIR_FUZZ"


def test_port_scan_signature_mapping():
    """Verify network connection probe maps to registered PORT_SCAN signature."""
    with patch('security_agent.detector.AlertClient') as mock_client_cls:
        mock_client = mock_client_cls.return_value
        mock_client.send_event.return_value = (True, {})
        detector = ServerDetector(soc_url="http://test", api_key="k", port=5000)

        event = detector.record_network_connection(source_ip="192.168.31.200", destination_port=22)
        assert event["signature"] == "PORT_SCAN"
        assert event["event_type"] == "PORT_SCAN"
        assert event["destination_port"] == 22


def test_auth_brute_force_decay_and_burst():
    """Verify authentication failure counting, sliding window decay, and burst threshold."""
    with patch('security_agent.detector.AlertClient') as mock_client_cls:
        mock_client = mock_client_cls.return_value
        mock_client.send_event.return_value = (True, {})
        detector = ServerDetector(soc_url="http://test", api_key="k", port=5000)
        detector.auth_decay_seconds = 10  # short decay window for test

        ip = "192.168.1.150"

        # 1st attempt: LOGIN_FAILED, severity LOW
        evt1 = detector.record_auth_failure(ip, "alice")
        assert evt1["signature"] == "BRUTE_FORCE_AUTH"
        assert evt1["event_type"] == "LOGIN_FAILED"
        assert evt1["severity"] == "LOW"
        assert evt1["metadata"]["failure_count"] == 1

        # 2nd attempt: LOGIN_FAILED, severity LOW
        evt2 = detector.record_auth_failure(ip, "alice")
        assert evt2["metadata"]["failure_count"] == 2

        # 3rd attempt: AUTH_BRUTE_FORCE burst, severity HIGH
        evt3 = detector.record_auth_failure(ip, "alice")
        assert evt3["signature"] == "BRUTE_FORCE_AUTH"
        assert evt3["event_type"] == "AUTH_BRUTE_FORCE"
        assert evt3["severity"] == "HIGH"
        assert evt3["metadata"]["failure_count"] == 3

        # Simulate time passing beyond decay window
        detector.failed_logins[ip] = [time.time() - 20]  # 20 seconds ago

        # New attempt should be treated as fresh attempt 1
        evt_fresh = detector.record_auth_failure(ip, "alice")
        assert evt_fresh["event_type"] == "LOGIN_FAILED"
        assert evt_fresh["severity"] == "LOW"
        assert evt_fresh["metadata"]["failure_count"] == 1


def test_auth_success_clears_failures():
    """Verify successful login resets failure counter and logs LOGIN_SUCCESS."""
    with patch('security_agent.detector.AlertClient') as mock_client_cls:
        mock_client = mock_client_cls.return_value
        mock_client.send_event.return_value = (True, {})
        detector = ServerDetector(soc_url="http://test", api_key="k", port=5000)

        ip = "192.168.1.160"
        detector.record_auth_failure(ip, "admin")
        detector.record_auth_failure(ip, "admin")
        assert len(detector.failed_logins[ip]) == 2

        success_evt = detector.record_auth_success(ip, "admin")
        assert success_evt["event_type"] == "LOGIN_SUCCESS"
        assert ip not in detector.failed_logins


# ---------------------------------------------------------------------------
# 3. HTTP Response Handling & Spooling Tests
# ---------------------------------------------------------------------------

def test_http_202_accepted_treated_as_success(tmp_path):
    """Verify HTTP 202 Accepted is treated as success and not spooled."""
    client = AlertClient(soc_url="http://127.0.0.1:5050", api_key="test", spool_dir=str(tmp_path))
    client._flush_spool_quietly = MagicMock()

    with patch('requests.post') as mock_post:
        # Receiver returns 202 with non-JSON text
        mock_post.return_value.status_code = 202
        mock_post.return_value.text = "Accepted for processing"
        mock_post.return_value.json.side_effect = Exception("No JSON")

        success, res = client.send_event({"event_id": "EVT-1", "source_ip": "1.2.3.4", "signature": "PORT_SCAN"})
        assert success is True
        assert res["status"] == "accepted"
        assert res["status_code"] == 202
        # Verify nothing spooled
        assert not client.spool_file.exists() or client.spool_file.stat().st_size == 0


def test_http_4xx_permanent_errors_not_spooled(tmp_path):
    """Verify HTTP 400, 401, 403, 404 report distinct errors and are NOT spooled."""
    client = AlertClient(soc_url="http://127.0.0.1:5050", api_key="test", spool_dir=str(tmp_path))
    client._flush_spool_quietly = MagicMock()

    for code, expected_err in [(401, "Unauthorized"), (403, "Forbidden"), (404, "NotFound"), (400, "BadRequest")]:
        with patch('requests.post') as mock_post:
            mock_post.return_value.status_code = code
            mock_post.return_value.text = f"Error {code}"

            success, res = client.send_event({"event_id": f"EVT-{code}", "source_ip": "1.2.3.4", "signature": "PORT_SCAN"})
            assert success is False
            assert res["error"] == expected_err
            assert res["buffered"] is False
            assert not client.spool_file.exists() or client.spool_file.stat().st_size == 0


def test_http_500_server_error_buffered_to_spool(tmp_path):
    """Verify HTTP 500 triggers offline disk spooling for retry."""
    client = AlertClient(soc_url="http://127.0.0.1:5050", api_key="test", spool_dir=str(tmp_path))
    client._flush_spool_quietly = MagicMock()

    with patch('requests.post') as mock_post:
        mock_post.return_value.status_code = 500
        mock_post.return_value.text = "Internal Server Error"

        success, res = client.send_event({"event_id": "EVT-500", "source_ip": "1.2.3.4", "signature": "PORT_SCAN"})
        assert success is False
        assert res["buffered"] is True
        assert client.spool_file.exists()
        content = client.spool_file.read_text(encoding="utf-8")
        assert "EVT-500" in content


def test_connection_error_buffered_to_spool(tmp_path):
    """Verify network connection timeout or failure buffers event to disk."""
    import requests
    client = AlertClient(soc_url="http://127.0.0.1:5050", api_key="test", spool_dir=str(tmp_path))
    client._flush_spool_quietly = MagicMock()

    with patch('requests.post', side_effect=requests.exceptions.ConnectionError("Connection refused")):
        success, res = client.send_event({"event_id": "EVT-CONN", "source_ip": "1.2.3.4", "signature": "PORT_SCAN"})
        assert success is False
        assert res["error"] == "ConnectionError"
        assert res["buffered"] is True
        assert client.spool_file.exists()
        assert "EVT-CONN" in client.spool_file.read_text(encoding="utf-8")


def test_spool_replay_preserves_event_id(tmp_path):
    """Verify spool retry preserves original event_id and clears consumed entries on 202/409."""
    client = AlertClient(soc_url="http://127.0.0.1:5050", api_key="test", spool_dir=str(tmp_path))
    # Write 2 events to spool
    evt1 = {"event_id": "EVT-ORIG-01", "source_ip": "10.0.0.1", "signature": "PORT_SCAN"}
    evt2 = {"event_id": "EVT-ORIG-02", "source_ip": "10.0.0.2", "signature": "SQL_INJECTION"}
    client.spool_file.write_text(json.dumps(evt1) + "\n" + json.dumps(evt2) + "\n", encoding="utf-8")

    with patch('requests.post') as mock_post:
        # First event gets 202 Accepted, second gets 409 Conflict (already ingested)
        mock_post.side_effect = [
            MagicMock(status_code=202, text="Accepted"),
            MagicMock(status_code=409, text="Already exists")
        ]

        delivered = client.flush_spool()
        assert delivered == 2
        # Verify original event IDs were preserved in requests
        calls = mock_post.call_args_list
        assert calls[0][1]["json"]["event_id"] == "EVT-ORIG-01"
        assert calls[1][1]["json"]["event_id"] == "EVT-ORIG-02"
        # Verify spool file is now empty
        assert client.spool_file.read_text(encoding="utf-8") == ""


def test_validate_payload_rejects_missing_source_ip(tmp_path):
    """Verify validation catches empty source_ip before network request."""
    client = AlertClient(soc_url="http://127.0.0.1:5050", api_key="test", spool_dir=str(tmp_path))
    client._flush_spool_quietly = MagicMock()

    with patch('requests.post') as mock_post:
        success, res = client.send_event({"event_id": "EVT-BAD", "source_ip": "", "signature": "PORT_SCAN"})
        assert success is False
        assert res["error"] == "ValidationError"
        mock_post.assert_not_called()


# ---------------------------------------------------------------------------
# 4. Flask Application Integration Tests
# ---------------------------------------------------------------------------

def test_flask_form_body_sqli_inspection():
    """Verify Flask @before_request passes POST form body to detector."""
    client = app.test_client()
    with patch('app.detector') as mock_det:
        client.post('/', data={"username": "admin' or '1'='1", "password": "xyz"})
        mock_det.inspect_http_request.assert_called_once()
        kwargs = mock_det.inspect_http_request.call_args[1]
        assert "username=admin' or '1'='1" in kwargs["body"]


def test_flask_successful_login_calls_record_auth_success():
    """Verify valid login calls record_auth_success."""
    client = app.test_client()
    with patch('app.detector') as mock_det:
        resp = client.post('/', data={"username": "admin", "password": "admin123"})
        assert resp.status_code == 200
        assert b"Login successful" in resp.data
        mock_det.record_auth_success.assert_called_once_with(
            source_ip="127.0.0.1",
            username="admin"
        )
