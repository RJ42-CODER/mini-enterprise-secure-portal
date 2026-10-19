import pytest
import os
from unittest.mock import patch, MagicMock

# Mock env vars before importing anything that evaluates them at module level
os.environ["CN_SERVER_IP"] = "192.168.31.91"
os.environ["SOC_URL"] = "http://192.168.31.204:5050"
os.environ["SOC_API_KEY"] = "mock_test_token"

from security_agent.network_sniffer import NetworkSniffer
from security_agent.detector import ServerDetector
from flask import request
from app import app

def test_port_5000_not_canary():
    sniffer = NetworkSniffer()
    assert 5000 not in sniffer.monitored_ports

def test_tcpdump_parses_port_5000_and_filters_correctly():
    sniffer = NetworkSniffer()
    sniffer.handle_probe = MagicMock()
    sniffer.running = True
    
    sniffer._proc = MagicMock()
    
    # Without CN_SERVER_IP (simulated for test, we shouldn't really delete it now since detector requires it, let's just mock it)
    sniffer.handle_probe.reset_mock()
    os.environ["CN_SERVER_IP"] = "192.168.31.91"
    sniffer._proc.stdout = ["10:34:56.923614 enp0s8 In IP 192.168.31.204.59286 > 192.168.31.91.5000: Flags [S]"]
    sniffer._pcap_worker()
    sniffer.handle_probe.assert_called_with("192.168.31.204", 5000, protocol="TCP")

    # With non-matching CN_SERVER_IP
    sniffer.handle_probe.reset_mock()
    os.environ["CN_SERVER_IP"] = "192.168.31.92"
    sniffer._proc.stdout = ["10:34:56.923614 enp0s8 In IP 192.168.31.204.59286 > 192.168.31.91.5000: Flags [S]"]
    sniffer._pcap_worker()
    sniffer.handle_probe.assert_not_called()
    
    os.environ["CN_SERVER_IP"] = "192.168.31.91"  # Restore

def test_syn_produces_network_connection():
    detector_mock = MagicMock()
    sniffer = NetworkSniffer(detector=detector_mock)
    
    sniffer.handle_probe("192.168.31.204", 5000, protocol="TCP")
    
    detector_mock.record_network_connection.assert_called_with(
        source_ip="192.168.31.204",
        destination_port=5000,
        protocol="TCP",
        is_test=0
    )

def test_syn_ack_does_not_create_new_syn_event():
    sniffer = NetworkSniffer()
    sniffer.handle_probe = MagicMock()
    sniffer.running = True
    sniffer._proc = MagicMock()
    # SYN-ACK has [S.]
    sniffer._proc.stdout = ["10:34:56.923614 enp0s8 In IP 192.168.31.204.59286 > 192.168.31.91.5000: Flags [S.]"]
    sniffer._pcap_worker()
    sniffer.handle_probe.assert_not_called()

def test_duplicate_packets_deduplicated():
    sniffer = NetworkSniffer()
    sniffer.detector = MagicMock()
    # Same IP, Port within 1 second
    sniffer.handle_probe("192.168.31.204", 5000, protocol="TCP")
    sniffer.handle_probe("192.168.31.204", 5000, protocol="TCP")
    assert sniffer.detector.record_network_connection.call_count == 1

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
    # Unset SOC_URL
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

