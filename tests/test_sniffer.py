import pytest
import os
import time
from pathlib import Path
from unittest.mock import patch, MagicMock

# Mock env vars before importing anything that evaluates them at module level
os.environ["CN_SERVER_IP"] = "192.168.31.91"
os.environ["SOC_URL"] = "http://192.168.31.73:8443"
os.environ["SOC_API_KEY"] = "mock_test_token"

from security_agent.network_sniffer import NetworkSniffer, PortScanTracker, SingleInstanceLock
from security_agent.detector import ServerDetector
from flask import request
from app import app


# ---------------------------------------------------------------------------
# 1. Pcap Worker & Packet Parsing Tests
# ---------------------------------------------------------------------------

def test_port_5000_not_canary():
    """Ensure port 5000 is not in canary sentinel ports since Flask serves it."""
    sniffer = NetworkSniffer()
    assert 5000 not in sniffer.monitored_ports


def test_tcpdump_parses_port_5000_and_filters_correctly():
    """Verify tcpdump stdout regex parses IP, port, flags, timestamp and applies target filtering."""
    sniffer = NetworkSniffer()
    sniffer.handle_probe = MagicMock()
    sniffer.running = True
    sniffer._proc = MagicMock()

    # With matching CN_SERVER_IP
    sniffer.handle_probe.reset_mock()
    os.environ["CN_SERVER_IP"] = "192.168.31.91"
    sniffer._proc.stdout = ["10:34:56.923614 enp0s8 In IP 192.168.31.204.59286 > 192.168.31.91.5000: Flags [S]"]
    sniffer._pcap_worker()
    sniffer.handle_probe.assert_called_with(
        source_ip="192.168.31.204",
        destination_port=5000,
        protocol="TCP",
        flags="S",
        timestamp="10:34:56.923614",
        destination_ip="192.168.31.91"
    )

    # With non-matching CN_SERVER_IP (unrelated network traffic excluded)
    sniffer.handle_probe.reset_mock()
    os.environ["CN_SERVER_IP"] = "192.168.31.92"
    sniffer._proc.stdout = ["10:34:56.923614 enp0s8 In IP 192.168.31.204.59286 > 192.168.31.91.5000: Flags [S]"]
    sniffer._pcap_worker()
    sniffer.handle_probe.assert_not_called()

    os.environ["CN_SERVER_IP"] = "192.168.31.91"  # Restore


def test_syn_ack_does_not_create_new_syn_event():
    """Verify SYN-ACK responses [S.] are ignored by SYN scanner parser."""
    sniffer = NetworkSniffer()
    sniffer.handle_probe = MagicMock()
    sniffer.running = True
    sniffer._proc = MagicMock()
    sniffer._proc.stdout = ["10:34:56.923614 enp0s8 In IP 192.168.31.204.59286 > 192.168.31.91.5000: Flags [S.]"]
    sniffer._pcap_worker()
    sniffer.handle_probe.assert_not_called()


def test_tshark_tsv_parsing():
    """Verify tshark tab-separated output parsing."""
    sniffer = NetworkSniffer()
    sniffer.handle_probe = MagicMock()
    sniffer.running = True
    sniffer._proc = MagicMock()
    sniffer._proc.stdout = ["1729528000.123\t192.168.31.98\t192.168.31.91\t80\t0x0002"]
    sniffer._pcap_worker()
    sniffer.handle_probe.assert_called_with(
        source_ip="192.168.31.98",
        destination_port=80,
        protocol="TCP",
        flags="0x0002",
        timestamp="1729528000.123",
        destination_ip="192.168.31.91"
    )


# ---------------------------------------------------------------------------
# 2. Sliding-Window PortScanTracker Unit Tests
# ---------------------------------------------------------------------------

def test_distinct_ports_counting():
    """Verify distinct destination ports are accurately aggregated per source IP."""
    tracker = PortScanTracker(threshold=5, window_seconds=60, cooldown_seconds=30)
    ip = "192.168.31.98"

    for port in [21, 22, 80, 443]:
        detected, info = tracker.record_probe(ip, port)
        assert detected is False
        assert info is None

    # 5th distinct port crosses threshold
    detected, info = tracker.record_probe(ip, 8080)
    assert detected is True
    assert info is not None
    assert info["distinct_ports_count"] == 5
    assert info["observed_ports"] == [21, 22, 80, 443, 8080]
    assert info["source_ip"] == ip


def test_repeated_packets_to_same_port_ignored():
    """Verify multiple packets to the same destination port only count as 1 distinct port."""
    tracker = PortScanTracker(threshold=5, window_seconds=60, cooldown_seconds=30)
    ip = "192.168.31.98"

    # Send 20 probes targeting port 80 (e.g. HTTP flooding or retransmits)
    for _ in range(20):
        detected, info = tracker.record_probe(ip, 80)
        assert detected is False
        assert info is None

    # Probe 3 more distinct ports (total 4 distinct ports)
    for p in [21, 22, 443]:
        detected, info = tracker.record_probe(ip, p)
        assert detected is False
        assert info is None

    # 5th distinct port crosses threshold
    detected, info = tracker.record_probe(ip, 8443)
    assert detected is True
    assert info["distinct_ports_count"] == 5
    assert info["observed_ports"] == [21, 22, 80, 443, 8443]


def test_threshold_crossing_triggers_port_scan():
    """Verify aggregated alert metadata on threshold crossing."""
    tracker = PortScanTracker(threshold=3, window_seconds=30, cooldown_seconds=15, severity="HIGH")
    ip = "192.168.31.98"
    target = "192.168.31.91"

    tracker.record_probe(ip, 22, target_ip=target, flag="SYN", packet_time="10:00:01")
    tracker.record_probe(ip, 80, target_ip=target, flag="SYN", packet_time="10:00:02")
    detected, info = tracker.record_probe(ip, 443, target_ip=target, flag="SYN", packet_time="10:00:03")

    assert detected is True
    assert info["source_ip"] == ip
    assert info["target_ip"] == target
    assert info["distinct_ports_count"] == 3
    assert info["observed_ports"] == [22, 80, 443]
    assert info["detection_window"] == 30
    assert info["severity"] == "HIGH"
    assert "TCP port scan detected" in info["message"]
    assert "SYN" in info["tcp_flags"]


def test_sliding_window_expiry():
    """Verify probes older than window_seconds expire and do not contribute to threshold."""
    tracker = PortScanTracker(threshold=3, window_seconds=10, cooldown_seconds=5)
    ip = "192.168.31.98"

    # Probes at t=100
    tracker.record_probe(ip, 21, current_time=100.0)
    tracker.record_probe(ip, 22, current_time=100.0)

    # Fast-forward to t=115 (older probes from t=100 have expired since 115 - 100 > 10)
    detected, info = tracker.record_probe(ip, 80, current_time=115.0)
    assert detected is False  # Only 1 active probe in window [105, 115]

    # Add another probe at t=116
    detected, info = tracker.record_probe(ip, 443, current_time=116.0)
    assert detected is False  # Only 2 active probes in window [106, 116]

    # Add 3rd active probe at t=117 -> threshold reached
    detected, info = tracker.record_probe(ip, 8080, current_time=117.0)
    assert detected is True
    assert info["distinct_ports_count"] == 3
    assert info["observed_ports"] == [80, 443, 8080]


def test_cooldown_suppresses_duplicate_alerts():
    """Verify that after alert fires, further probes within cooldown do not re-alert."""
    tracker = PortScanTracker(threshold=3, window_seconds=60, cooldown_seconds=30)
    ip = "192.168.31.98"

    # Trigger initial alert at t=100
    tracker.record_probe(ip, 21, current_time=100.0)
    tracker.record_probe(ip, 22, current_time=100.0)
    detected, info = tracker.record_probe(ip, 80, current_time=100.0)
    assert detected is True

    # Additional probes at t=105 and t=115 (within cooldown 30s)
    detected_cd1, _ = tracker.record_probe(ip, 443, current_time=105.0)
    assert detected_cd1 is False

    detected_cd2, _ = tracker.record_probe(ip, 8080, current_time=115.0)
    assert detected_cd2 is False


def test_continued_scans_trigger_new_alert_after_cooldown():
    """Verify that continued scanning after cooldown triggers a subsequent aggregated alert."""
    tracker = PortScanTracker(threshold=3, window_seconds=60, cooldown_seconds=30)
    ip = "192.168.31.98"

    # Initial alert at t=100
    tracker.record_probe(ip, 21, current_time=100.0)
    tracker.record_probe(ip, 22, current_time=100.0)
    detected1, _ = tracker.record_probe(ip, 80, current_time=100.0)
    assert detected1 is True

    # Scanning continues at t=135 (35s later, cooldown has passed)
    detected2, info2 = tracker.record_probe(ip, 443, current_time=135.0)
    assert detected2 is True
    assert info2["distinct_ports_count"] == 4
    assert 443 in info2["observed_ports"]


def test_bounded_memory_pruning():
    """Verify tracker enforces bounded memory and prunes stale IPs."""
    tracker = PortScanTracker(threshold=5, window_seconds=10, cooldown_seconds=5, max_tracked_ips=3)

    # Add probes from 5 different IPs
    for i in range(1, 6):
        tracker.record_probe(f"10.0.0.{i}", 80, current_time=100.0)

    # Verify memory is bounded by max_tracked_ips
    assert tracker.get_tracked_ip_count() <= 3


def test_source_ip_isolation():
    """Verify probes from different IPs do not cross-contaminate counts."""
    tracker = PortScanTracker(threshold=4, window_seconds=60, cooldown_seconds=30)

    # IP 1 probes 3 ports
    for p in [21, 22, 80]:
        tracker.record_probe("10.0.0.1", p)

    # IP 2 probes 3 ports
    for p in [443, 8080, 8443]:
        tracker.record_probe("10.0.0.2", p)

    # Neither should have triggered
    assert tracker.last_alert_time.get("10.0.0.1") is None
    assert tracker.last_alert_time.get("10.0.0.2") is None


# ---------------------------------------------------------------------------
# 3. NetworkSniffer & End-to-End SOC Telemetry Tests
# ---------------------------------------------------------------------------

def test_event_delivery_to_alert_client():
    """Verify end-to-end detection flow from probe to SOC AlertClient delivery."""
    detector = ServerDetector(soc_url="http://192.168.31.73:8443", api_key="test_key", port=5000)
    detector.client.send_event = MagicMock(return_value=(True, {"status": "accepted"}))

    sniffer = NetworkSniffer(
        detector=detector,
        scan_threshold=3,
        scan_window=60,
        scan_cooldown=30,
        scan_severity="HIGH"
    )

    ip = "192.168.31.98"
    sniffer.handle_probe(ip, 21, protocol="TCP")
    sniffer.handle_probe(ip, 22, protocol="TCP")
    event = sniffer.handle_probe(ip, 80, protocol="TCP")

    assert event is not None
    assert event["event_type"] == "PORT_SCAN"
    assert event["signature"] == "PORT_SCAN"
    assert event["severity"] == "HIGH"
    assert event["source_ip"] == ip
    assert event["destination_ip"] == "192.168.31.91"
    assert event["metadata"]["mitre_technique"] == "T1046"
    assert event["metadata"]["mitre_name"] == "Network Service Discovery"
    assert event["metadata"]["distinct_ports_count"] == 3
    assert event["metadata"]["observed_ports"] == [21, 22, 80]

    # Verify AlertClient was invoked with this event
    detector.client.send_event.assert_called_once()
    sent_payload = detector.client.send_event.call_args[0][0]
    assert sent_payload["event_id"] == event["event_id"]
    assert sent_payload["signature"] == "PORT_SCAN"


def test_single_instance_lock(tmp_path):
    """Verify SingleInstanceLock prevents concurrent duplicate sniffer processes."""
    pid_file = tmp_path / "test_sniffer.pid"
    lock1 = SingleInstanceLock(pid_file)
    lock2 = SingleInstanceLock(pid_file)

    assert lock1.acquire() is True
    # Second acquisition must fail
    assert lock2.acquire() is False

    # Release first lock
    lock1.release()

    # Second acquisition now succeeds
    assert lock2.acquire() is True
    lock2.release()


def test_single_instance_lock_with_preexisting_pid_file(tmp_path):
    """Verify SingleInstanceLock acquires and releases cleanly even if PID file exists with prior content."""
    pid_file = tmp_path / "test_sniffer.pid"
    pid_file.write_text("999999\n", encoding="utf-8")

    lock1 = SingleInstanceLock(pid_file)
    lock2 = SingleInstanceLock(pid_file)

    assert lock1.acquire() is True
    assert lock2.acquire() is False
    lock1.release()

    assert lock2.acquire() is True
    lock2.release()



def test_target_ip_filtering_excludes_other_destinations():
    """Verify handle_probe rejects probes where destination_ip != CN_SERVER_IP."""
    detector_mock = MagicMock()
    sniffer = NetworkSniffer(detector=detector_mock, scan_threshold=1)
    os.environ["CN_SERVER_IP"] = "192.168.31.91"

    # Probe directed to another host on the network
    res = sniffer.handle_probe(
        source_ip="192.168.31.98",
        destination_port=80,
        destination_ip="192.168.31.200"
    )
    assert res is None
    detector_mock.record_port_scan.assert_not_called()


def test_loopback_probes_allow_localhost():
    """Verify loopback traffic is filtered when allow_localhost is False."""
    detector_mock = MagicMock()
    sniffer = NetworkSniffer(detector=detector_mock, scan_threshold=1, allow_localhost=False)

    res = sniffer.handle_probe(source_ip="127.0.0.1", destination_port=80)
    assert res is None
    detector_mock.record_port_scan.assert_not_called()


# ---------------------------------------------------------------------------
# 4. Existing Portal & Auth Tests (Preserved)
# ---------------------------------------------------------------------------

def test_failed_login_generates_login_failed():
    client = app.test_client()
    with patch('app.detector') as mock_detector:
        response = client.post('/', data={'username': 'admin', 'password': 'wrongpassword'})
        mock_detector.record_auth_failure.assert_called_once()
        args, kwargs = mock_detector.record_auth_failure.call_args
        assert kwargs['username'] == 'admin'


def test_suspicious_http_requests():
    client = app.test_client()
    with patch('app.detector') as mock_detector:
        client.get('/?test=../etc/passwd')
        mock_detector.inspect_http_request.assert_called_once()
        args, kwargs = mock_detector.inspect_http_request.call_args
        assert '../etc/passwd' in kwargs['query_string']


def test_normal_http_requests():
    client = app.test_client()
    with patch('app.detector') as mock_detector:
        client.get('/')
        mock_detector.inspect_http_request.assert_called_once()


def test_detector_returns_none_for_normal_request():
    with patch('security_agent.detector.AlertClient') as mock_client:
        detector = ServerDetector(soc_url="http://test", api_key="test")
        res = detector.inspect_http_request(
            source_ip="127.0.0.1",
            path="/",
            method="GET",
            headers={"User-Agent": "Mozilla/5.0"},
            query_string=""
        )
        assert res is None


def test_alert_client_sends_to_api():
    from security_agent.alert_client import AlertClient
    client = AlertClient(soc_url="http://127.0.0.1:5050", api_key="test")
    client._flush_spool_quietly = MagicMock()
    with patch('requests.post') as mock_post:
        mock_post.return_value.status_code = 200
        mock_post.return_value.json.return_value = {"status": "success"}
        success, res = client.send_event({"test": "data"})
        assert success is True
        mock_post.assert_called_once()
        assert mock_post.call_args[0][0] == "http://127.0.0.1:5050/api/events"


def test_missing_soc_url_raises_value_error():
    from security_agent.alert_client import AlertClient
    original_soc = os.environ.get("SOC_URL")
    if "SOC_URL" in os.environ:
        del os.environ["SOC_URL"]

    with pytest.raises(ValueError, match="SOC_URL is not configured"):
        AlertClient()

    if original_soc:
        os.environ["SOC_URL"] = original_soc


def test_missing_cn_server_ip_raises_value_error():
    original_cn = os.environ.get("CN_SERVER_IP")
    if "CN_SERVER_IP" in os.environ:
        del os.environ["CN_SERVER_IP"]

    with pytest.raises(ValueError, match="CN_SERVER_IP is not configured"):
        ServerDetector(soc_url="http://test")

    if original_cn:
        os.environ["CN_SERVER_IP"] = original_cn


def test_asset_name_protected_web_server():
    with patch('security_agent.detector.AlertClient') as mock_client:
        mock_client.return_value.send_event.return_value = (True, {})
        detector = ServerDetector(soc_url="http://test")
        event = detector.record_network_connection("1.2.3.4", 80)
        assert event["metadata"]["asset"] == f"Protected Web Server ({os.environ['CN_SERVER_IP']})"
