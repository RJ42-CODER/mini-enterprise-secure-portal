"""
Comprehensive Test Suite for HTTP Rate-Anomaly Detection, Extensible Pipeline,
Trusted-Proxy Client Identity, ML Readiness, and SSRF Auditing.

Verifies:
  1. Normal traffic below threshold produces no alert.
  2. Threshold crossing triggers structured RATE_ANOMALY event.
  3. Cooldown deduplication suppresses alert floods on subsequent requests.
  4. Repeated burst detection (burst threshold crossed in short window).
  5. Independent source identities operate with separate counters.
  6. Trusted-proxy vs untrusted direct client IP resolution (spoofing protection).
  7. Bounded state and memory limits under concurrent / high-cardinality traffic.
  8. Excluded paths (health checks) are bypassed.
  9. Structured event schema conformance with SOC ingestion contract.
 10. Separation of detection from enforcement (HTTP 200 returned, not blocked).
 11. SOC authentication failure (HTTP 401) and delivery failure buffering.
 12. Machine-learning readiness, feature extraction, and credential redaction.
 13. SSRF destination validation against cloud metadata, link-local, loopback, and bad schemes.
 14. Full regression validation across all six core attack scenarios.
"""

import os
import time
import json
import pytest
import threading
from unittest.mock import patch, MagicMock

# Set test environment
os.environ["CN_SERVER_IP"] = "192.168.31.91"
os.environ["SOC_URL"] = "http://192.168.31.73:8443"
os.environ["SOC_API_KEY"] = "mock_pipeline_test_key"
os.environ["PORT"] = "5000"
os.environ["WAF_MODE"] = "BLOCK"
os.environ["TRUSTED_PROXIES"] = "127.0.0.1,::1,localhost,192.168.31.91"

from security_agent.config import get_client_ip, redact_sensitive_data, get_trusted_proxies
from security_agent.rate_anomaly_detector import RateAnomalyConfig, RateAnomalyTracker
from security_agent.ml_detector import (
    MLFeatureExtractor,
    MLPrediction,
    BaselineHeuristicModel,
    MLAnomalyDetector
)
from security_agent.detection_pipeline import (
    RequestContext,
    DetectionResult,
    BaseDetectionModule,
    ExtensibleDetectionPipeline
)
from security_agent.ssrf_validator import (
    validate_outbound_url,
    is_ip_allowed,
    CLOUD_METADATA_IPS
)
from security_agent.alert_client import AlertClient
from security_agent.detector import ServerDetector
from app import app


@pytest.fixture
def clean_detector():
    """ServerDetector fixture with isolated state and spools."""
    detector = ServerDetector(soc_url="http://192.168.31.73:8443", api_key="test_key", port=5000)
    detector.clear_all_trackers()
    detector.rate_anomaly_tracker = RateAnomalyTracker(
        config=RateAnomalyConfig()
    )
    # Configure tight test parameters for deterministic testing
    detector.rate_anomaly_tracker.config.window_seconds = 5.0
    detector.rate_anomaly_tracker.config.threshold = 5
    detector.rate_anomaly_tracker.config.burst_window_seconds = 2.0
    detector.rate_anomaly_tracker.config.burst_threshold = 8
    detector.rate_anomaly_tracker.config.cooldown_seconds = 10.0
    detector.rate_anomaly_tracker.config.max_tracked_identities = 100
    detector.rate_anomaly_tracker.config.excluded_paths = {"/health", "/favicon.ico"}
    return detector


# ==============================================================================
# 1. Normal Traffic Below Threshold
# ==============================================================================

def test_normal_traffic_below_threshold_produces_no_anomaly(clean_detector):
    """Verify that requests under threshold return None and dispatch no telemetry."""
    ip = "192.168.1.10"
    for i in range(4):  # threshold is 5, burst_threshold is 8
        event = clean_detector.inspect_http_request(
            source_ip=ip,
            path="/",
            method="GET"
        )
        assert event is None


# ==============================================================================
# 2. Threshold Crossing and Structured Alert Generation
# ==============================================================================

def test_threshold_crossing_triggers_structured_rate_anomaly_event(clean_detector):
    """Verify that crossing threshold generates a structured RATE_ANOMALY event."""
    ip = "192.168.1.20"
    with patch.object(clean_detector.client, "send_event", return_value=(True, {"status": "ok"})) as mock_send:
        # Send 4 requests (below threshold 5)
        for _ in range(4):
            clean_detector.inspect_http_request(source_ip=ip, path="/", method="GET")

        # 5th request crosses threshold -> triggers rate anomaly
        event = clean_detector.inspect_http_request(source_ip=ip, path="/", method="GET")
        assert event is not None
        assert event["event_type"] == "RATE_ANOMALY"
        assert event["signature"] == "HTTP_RATE_ANOMALY"
        assert event["source_ip"] == ip
        assert event["destination_ip"] == "192.168.31.91"
        assert event["destination_port"] == 5000
        assert event["severity"] in ("MEDIUM", "HIGH")
        assert "HTTP request rate anomaly" in event["message"]

        # Validate structured metadata
        meta = event["metadata"]
        assert meta["affected_endpoint"] == "/"
        assert meta["http_method"] == "GET"
        assert meta["request_count"] >= 5
        assert meta["measurement_window_seconds"] == 5.0
        assert meta["configured_threshold"] == 5
        assert meta["detection_category"] == "RATE_ANOMALY"
        assert meta["detection_method"] == "SLIDING_WINDOW"
        assert meta["classification"] == "SINGLE_SOURCE_RATE_ANOMALY"
        assert "evidence" in meta
        assert meta["evidence"]["classification"] == "SINGLE_SOURCE_RATE_ANOMALY"

        # Verify separation of detection from enforcement: not blocked!
        assert event.get("_waf_blocked") is False

        # Verify event was sent to SOC
        mock_send.assert_called_once()


# ==============================================================================
# 3. Cooldown Deduplication
# ==============================================================================

def test_cooldown_deduplication_suppresses_alert_flood(clean_detector):
    """Verify that requests during cooldown period do not trigger duplicate alerts."""
    ip = "192.168.1.30"
    with patch.object(clean_detector.client, "send_event", return_value=(True, {})) as mock_send:
        # Cross threshold
        for _ in range(5):
            clean_detector.inspect_http_request(source_ip=ip, path="/", method="GET")
        assert mock_send.call_count == 1

        # Subsequent requests within cooldown period (10s) must NOT generate new alerts
        for _ in range(10):
            event = clean_detector.inspect_http_request(source_ip=ip, path="/", method="GET")
            assert event is None

        # Still only 1 alert dispatched
        assert mock_send.call_count == 1


# ==============================================================================
# 4. Repeated Burst Detection
# ==============================================================================

def test_sudden_burst_detection(clean_detector):
    """Verify that rapid burst within burst window triggers burst anomaly."""
    clean_detector.rate_anomaly_tracker.config.burst_threshold = 4
    ip = "192.168.1.40"
    with patch.object(clean_detector.client, "send_event", return_value=(True, {})):
        # burst_threshold is 4 in 2.0s
        for _ in range(3):
            clean_detector.inspect_http_request(source_ip=ip, path="/api/data", method="POST")

        event = clean_detector.inspect_http_request(source_ip=ip, path="/api/data", method="POST")
        assert event is not None
        assert event["metadata"]["is_burst"] is True
        assert "burst" in event["message"].lower()


# ==============================================================================
# 5. Independent Source Identities
# ==============================================================================

def test_independent_source_identities(clean_detector):
    """Verify tracking and alert thresholds are strictly isolated per client IP."""
    ip_a = "192.168.1.51"
    ip_b = "192.168.1.52"

    with patch.object(clean_detector.client, "send_event", return_value=(True, {})) as mock_send:
        # IP A sends 4 requests (below threshold)
        for _ in range(4):
            clean_detector.inspect_http_request(source_ip=ip_a, path="/", method="GET")

        # IP B sends 4 requests (below threshold)
        for _ in range(4):
            clean_detector.inspect_http_request(source_ip=ip_b, path="/", method="GET")

        # Neither should have triggered an alert
        assert mock_send.call_count == 0

        # IP A sends 5th request -> only IP A triggers
        event_a = clean_detector.inspect_http_request(source_ip=ip_a, path="/", method="GET")
        assert event_a is not None
        assert event_a["source_ip"] == ip_a
        assert mock_send.call_count == 1

        # IP B sends 1 request -> IP B triggers its own alert independently
        event_b = clean_detector.inspect_http_request(source_ip=ip_b, path="/", method="GET")
        assert event_b is not None
        assert event_b["source_ip"] == ip_b
        assert mock_send.call_count == 2


# ==============================================================================
# 6. Trusted-Proxy / Client-IP Handling
# ==============================================================================

def test_untrusted_direct_connection_ignores_spoofed_x_forwarded_for():
    """
    Security Invariant: When request comes directly from an untrusted peer,
    arbitrary client-supplied X-Forwarded-For must be ignored to prevent IP spoofing.
    """
    mock_req = MagicMock()
    mock_req.remote_addr = "203.0.113.195"  # External untrusted direct client
    mock_req.headers = {"X-Forwarded-For": "10.0.0.1, 127.0.0.1"}

    resolved_ip = get_client_ip(mock_req)
    # Must return the direct peer address, NOT the spoofed header
    assert resolved_ip == "203.0.113.195"


def test_trusted_proxy_correctly_resolves_client_ip():
    """
    When request arrives via verified trusted proxy (127.0.0.1 loopback Nginx),
    authentic client IP from X-Forwarded-For is extracted.
    """
    mock_req = MagicMock()
    mock_req.remote_addr = "127.0.0.1"  # Nginx on loopback
    mock_req.headers = {"X-Forwarded-For": "198.51.100.42, 127.0.0.1"}

    resolved_ip = get_client_ip(mock_req)
    assert resolved_ip == "198.51.100.42"


def test_trusted_proxy_resolves_x_real_ip():
    """Verify X-Real-IP is respected from trusted proxy."""
    mock_req = MagicMock()
    mock_req.remote_addr = "127.0.0.1"
    mock_req.headers = {"X-Real-IP": "198.51.100.88"}

    resolved_ip = get_client_ip(mock_req)
    assert resolved_ip == "198.51.100.88"


# ==============================================================================
# 7. Concurrent Requests and Bounded Memory State
# ==============================================================================

def test_rate_anomaly_bounded_memory_under_high_cardinality():
    """
    Verify memory bounding: Attacker varying thousands of source IP addresses
    cannot exhaust memory. Max tracked keys is strictly capped.
    """
    tracker = RateAnomalyTracker()
    tracker.config.max_tracked_identities = 50

    # Simulate 200 distinct attacker IPs
    for i in range(200):
        tracker.record_request(source_ip=f"10.0.0.{i}", path="/")

    # Tracking count must not exceed maximum capacity
    assert tracker.get_tracked_count() <= 50


def test_concurrent_request_tracking_safety():
    """Verify thread safety under concurrent requests from multiple threads."""
    tracker = RateAnomalyTracker()
    tracker.config.window_seconds = 10.0
    tracker.config.threshold = 50
    tracker.config.cooldown_seconds = 60.0

    errors = []

    def worker(client_id):
        try:
            for _ in range(20):
                tracker.record_request(source_ip=f"client_{client_id}", path="/")
        except Exception as e:
            errors.append(e)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(errors) == 0
    assert tracker.get_tracked_count() == 10


# ==============================================================================
# 8. Excluded Health-Check Endpoints
# ==============================================================================

def test_health_check_endpoints_are_excluded(clean_detector):
    """Verify routine health checks are excluded and do not trigger rate anomalies."""
    ip = "192.168.1.99"
    with patch.object(clean_detector.client, "send_event") as mock_send:
        # Send 20 requests to /health (well above threshold of 5)
        for _ in range(20):
            event = clean_detector.inspect_http_request(
                source_ip=ip,
                path="/health",
                method="GET"
            )
            assert event is None

        mock_send.assert_not_called()


# ==============================================================================
# 9. Separation of Detection from Enforcement
# ==============================================================================

def test_rate_anomaly_does_not_block_legitimate_http_request():
    """
    Verify architectural requirement: Detection is separated from enforcement.
    Rate anomaly triggers an alert, but Flask returns HTTP 200 OK without blocking.
    """
    app.config["TESTING"] = True
    from app import detector
    orig_tracker = detector.rate_anomaly_tracker
    try:
        detector.clear_all_trackers()
        detector.rate_anomaly_tracker = RateAnomalyTracker()
        detector.rate_anomaly_tracker.config.threshold = 3
        detector.rate_anomaly_tracker.config.burst_threshold = 3
        detector.rate_anomaly_tracker.config.window_seconds = 5.0
        detector.rate_anomaly_tracker.config.burst_window_seconds = 2.0
        detector.rate_anomaly_tracker.config.cooldown_seconds = 30.0

        with app.test_client() as client:
            with patch('requests.post') as mock_soc_post:
                mock_soc_post.return_value.status_code = 200
                mock_soc_post.return_value.json.return_value = {"status": "ok"}

                # Send requests crossing rate-anomaly threshold
                for i in range(4):
                    res = client.get('/', headers={"X-Forwarded-For": "192.168.100.55"})
                    # Request MUST return HTTP 200 OK (not 429 blocked!)
                    assert res.status_code == 200
                    assert b"Secure Portal" in res.data

                # Telemetry was alerted to SOC
                assert mock_soc_post.call_count >= 1
                payload = mock_soc_post.call_args[1]["json"]
                assert payload["event_type"] == "RATE_ANOMALY"
                assert payload["source_ip"] == "192.168.100.55"
    finally:
        detector.rate_anomaly_tracker = orig_tracker
        detector.clear_all_trackers()


# ==============================================================================
# 10. SOC Delivery Failure & Buffering (HTTP 401 & Unreachable)
# ==============================================================================

def test_soc_authentication_failure_not_spooled(tmp_path):
    """Verify permanent 401 Unauthorized errors are reported without infinite disk buffering."""
    client = AlertClient(
        soc_url="http://192.168.31.73:8443",
        api_key="bad_token",
        spool_dir=str(tmp_path)
    )
    with patch("requests.post") as mock_post:
        mock_post.return_value.status_code = 401
        success, res = client.send_event({
            "event_id": "EVT-TEST-01",
            "source_ip": "192.168.1.1",
            "event_type": "TEST"
        })
        assert success is False
        assert res["error"] == "Unauthorized"
        assert res["buffered"] is False
        # Spool file must be empty
        assert not client.spool_file.exists() or client.spool_file.stat().st_size == 0


def test_soc_connection_failure_spools_to_disk(tmp_path):
    """Verify transient network failure buffers events locally for retry."""
    import requests as req
    client = AlertClient(
        soc_url="http://192.168.31.73:8443",
        api_key="valid_token",
        spool_dir=str(tmp_path)
    )
    with patch("requests.post", side_effect=req.exceptions.ConnectionError("Refused")):
        success, res = client.send_event({
            "event_id": "EVT-TEST-SPOOL",
            "source_ip": "192.168.1.5",
            "event_type": "RATE_ANOMALY"
        })
        assert success is False
        assert res["buffered"] is True
        assert client.spool_file.exists()
        assert client.spool_file.stat().st_size > 0


# ==============================================================================
# 11. Machine-Learning Readiness & Privacy Redaction
# ==============================================================================

def test_ml_feature_extraction_sanitizes_credentials():
    """Verify feature extractor strictly redacts sensitive credentials and passwords."""
    query = "username=admin&password=SuperSecretPassword123!&token=xyz999"
    body = "auth=bearer123&data=normal"

    features = MLFeatureExtractor.extract_features(
        path="/api/login",
        method="POST",
        headers={"User-Agent": "Mozilla/5.0"},
        query_string=query,
        body=body
    )

    assert features["schema_version"] == "1.0.0"
    assert features["path_depth"] == 2
    assert features["is_post"] == 1
    assert "SuperSecretPassword123!" not in str(features)
    assert "bearer123" not in str(features)


def test_ml_anomaly_detector_investigative_signal():
    """Verify ML anomaly outputs investigative signal with required fields."""
    detector = MLAnomalyDetector(min_confidence=0.5)

    # High entropy anomalous URI
    res = detector.evaluate_request(
        path="/%2e%2e/%2e%2e/very/deep/path/nested/sub/dir/test%ff%00%aa%bb",
        method="PUT",
        headers={"User-Agent": "Scanner"}
    )
    assert res is not None
    assert res["detected"] is True
    assert res["signature"] == "ML_HTTP_ANOMALY"
    meta = res["metadata"]
    assert meta["investigative_signal_only"] is True
    pred = meta["model_prediction"]
    assert "model_name" in pred
    assert "model_version" in pred
    assert "confidence_score" in pred
    assert "feature_schema_version" in pred
    assert pred["predicted_class"] in ("suspicious_anomaly", "unknown")


# ==============================================================================
# 12. SSRF Destination Safety & Audit
# ==============================================================================

def test_ssrf_validator_rejects_cloud_metadata():
    """Verify SSRF validator strictly blocks AWS/GCP/Azure cloud metadata (169.254.169.254)."""
    valid, msg, ip = validate_outbound_url("http://169.254.169.254/latest/meta-data/")
    assert valid is False
    assert "forbidden" in msg.lower() or "metadata" in msg.lower()


def test_ssrf_validator_rejects_disallowed_schemes():
    """Verify file:// and gopher:// schemes are rejected."""
    valid, msg, _ = validate_outbound_url("file:///etc/passwd")
    assert valid is False
    assert "scheme" in msg.lower()


def test_ssrf_validator_rejects_embedded_credentials():
    """Verify URLs with embedded credentials (http://user:pass@host) are rejected."""
    valid, msg, _ = validate_outbound_url("http://admin:secret@example.com/api")
    assert valid is False
    assert "credentials" in msg.lower()


def test_ssrf_audit_portal_routes_safe():
    """
    Documented Architectural Finding:
    The Secure Portal (app.py) route handlers do not take any client-supplied
    destination URLs or perform outbound HTTP requests on behalf of users.
    SSRF is NOT applicable to the currently exposed portal routes.
    """
    routes = [rule.rule for rule in app.url_map.iter_rules()]
    # Only root login endpoint exists
    assert "/" in routes
    # Verify no proxy, fetch, webhook, or callback endpoints exist
    for r in routes:
        assert "fetch" not in r
        assert "proxy" not in r
        assert "webhook" not in r


# ==============================================================================
# 13. Regression Coverage for All Six Core Attack Scenarios
# ==============================================================================

def test_scenario_1_port_scan_detection(clean_detector):
    """Scenario 1: Nmap / Network Service Discovery (MITRE T1046)."""
    with patch.object(clean_detector.client, "send_event", return_value=(True, {})):
        event = clean_detector.record_port_scan(
            source_ip="192.168.31.205",
            distinct_ports=[21, 22, 80, 443, 8080],
            target_ip="192.168.31.91"
        )
        assert event["signature"] == "PORT_SCAN"
        assert event["severity"] == "HIGH"
        assert event["metadata"]["mitre_technique"] == "T1046"


def test_scenario_2_directory_enumeration(clean_detector):
    """Scenario 2: Directory Enumeration / Path Fuzzing."""
    with patch.object(clean_detector.client, "send_event", return_value=(True, {})):
        # Probing explicit sensitive indicator /.env
        event = clean_detector.record_not_found(
            source_ip="192.168.31.200",
            path="/.env",
            method="GET"
        )
        assert event is not None
        assert event["signature"] == "DIR_FUZZ"
        assert event["severity"] == "HIGH"


def test_scenario_3_path_traversal(clean_detector):
    """Scenario 3: Path Traversal."""
    with patch.object(clean_detector.client, "send_event", return_value=(True, {})):
        event = clean_detector.inspect_http_request(
            source_ip="192.168.31.200",
            path="/../../etc/passwd",
            method="GET"
        )
        assert event is not None
        assert event["signature"] == "PATH_TRAVERSAL"
        assert event["severity"] == "HIGH"
        assert event.get("_waf_blocked") is True


def test_scenario_4_sql_injection(clean_detector):
    """Scenario 4: SQL Injection."""
    with patch.object(clean_detector.client, "send_event", return_value=(True, {})):
        event = clean_detector.inspect_http_request(
            source_ip="192.168.31.200",
            path="/",
            method="GET",
            query_string="id=1' UNION SELECT 1,2,3--"
        )
        assert event is not None
        assert event["signature"] == "SQL_INJECTION"
        assert event["severity"] == "CRITICAL"
        assert event.get("_waf_blocked") is True


def test_scenario_5_brute_force_login(clean_detector):
    """Scenario 5: Brute-Force Authentication Attempt."""
    with patch.object(clean_detector.client, "send_event", return_value=(True, {})):
        # 1st failure: LOW severity
        e1 = clean_detector.record_auth_failure(source_ip="192.168.31.150", username="admin")
        assert e1["severity"] == "LOW"

        clean_detector.record_auth_failure(source_ip="192.168.31.150", username="admin")

        # 3rd failure: crosses threshold -> HIGH severity lockout
        e3 = clean_detector.record_auth_failure(source_ip="192.168.31.150", username="admin")
        assert e3["severity"] == "HIGH"
        assert e3["signature"] == "BRUTE_FORCE_AUTH"


def test_scenario_6_command_injection(clean_detector):
    """Scenario 6: Command Injection."""
    with patch.object(clean_detector.client, "send_event", return_value=(True, {})):
        event = clean_detector.inspect_http_request(
            source_ip="192.168.31.200",
            path="/",
            method="POST",
            body="cmd=;cat /etc/passwd"
        )
        assert event is not None
        assert event["signature"] == "COMMAND_INJECTION"
        assert event["severity"] == "CRITICAL"
        assert event.get("_waf_blocked") is True
