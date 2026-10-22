import os
import time
import json
import pytest
from unittest.mock import patch, MagicMock

# Configure environment before module imports
os.environ["CN_SERVER_IP"] = "192.168.31.91"
os.environ["SOC_URL"] = "http://192.168.31.73:8443"
os.environ["SOC_API_KEY"] = "test_defensive_controls_key"
os.environ["PORT"] = "5000"
os.environ["WAF_MODE"] = "BLOCK"
os.environ["WAF_AUTH_LOCKOUT_THRESHOLD"] = "3"
os.environ["WAF_AUTH_LOCKOUT_SECONDS"] = "2"
os.environ["WAF_AUTH_LOCKOUT_MAX_SECONDS"] = "60"
os.environ["WAF_DIR_FUZZ_THROTTLE_SECONDS"] = "3"
os.environ["DIR_FUZZ_THRESHOLD"] = "5"
os.environ["DIR_FUZZ_WINDOW_SECONDS"] = "60"

from security_agent.waf import WAFConfig, WAFInspector, BruteForceProtector, DirectoryFuzzTracker
from security_agent.detector import ServerDetector
from security_agent.defense_policy import SafeDefensivePolicy
from app import app


@pytest.fixture
def defensive_test_client():
    """Flask client fixture with isolated WAF, trackers, and spools."""
    app.config["TESTING"] = True
    from app import detector
    with patch.object(detector.client, '_flush_spool_quietly'):
        detector.failed_logins.clear()
        detector.waf.brute_force_protector = BruteForceProtector(
            threshold=3, lockout_seconds=2, decay_seconds=10, max_lockout_seconds=60
        )
        detector.fuzz_tracker = DirectoryFuzzTracker(
            threshold=5, window_seconds=60, cooldown_seconds=2, throttle_seconds=3
        )
        detector.waf.fuzz_tracker = detector.fuzz_tracker
        detector.defense_policy = SafeDefensivePolicy()
        detector.mitigation_history.clear()

        with app.test_client() as client:
            yield client, detector


# ==============================================================================
# 1. Progressive Brute-Force Lockout & Exponential Escalation
# ==============================================================================

def test_progressive_lockout_exponential_tier_escalation(defensive_test_client):
    """
    Verify progressive brute-force lockout:
      - 3 failures -> Tier 1 lockout (duration: 2s). Subsequent login blocked with 429 & Retry-After.
      - Upon next failure after expiry -> Tier 2 lockout (duration: 4s). Subsequent login blocked.
      - Structured verification evidence recorded for each tier with empirical proof.
    """
    client, detector = defensive_test_client

    with patch('requests.post'):
        # Failures 1 and 2: Allowed to attempt login, returns 200 invalid credentials
        r1 = client.post('/', data={"username": "admin", "password": "bad1"})
        assert r1.status_code == 200
        assert b"Invalid username or password" in r1.data

        r2 = client.post('/', data={"username": "admin", "password": "bad2"})
        assert r2.status_code == 200

        # Failure 3: Crosses lockout threshold (3) -> Triggers Tier 1 lockout
        r3 = client.post('/', data={"username": "admin", "password": "bad3"})
        assert r3.status_code == 200

        # Attempt 4 (during Tier 1 lockout): Intercepted at perimeter by WAF, returns HTTP 429
        r4 = client.post('/', data={"username": "admin", "password": "any"})
        assert r4.status_code == 429
        assert b"IP temporarily locked out" in r4.data
        assert "Retry-After" in r4.headers
        assert int(r4.headers["Retry-After"]) >= 1

        # Verify Tier 1 mitigation record
        history = detector.get_mitigation_history()
        tier1_records = [m for m in history if m["attack_type"] == "BRUTE_FORCE_AUTH" and m["action_taken"] == "LOCKED_OUT"]
        assert len(tier1_records) >= 1
        t1_evidence = tier1_records[-1]["verification_evidence"]
        assert t1_evidence["lockout_tier"] == 1
        assert t1_evidence["lockout_duration_seconds"] == 2
        assert t1_evidence["perimeter_enforced"] is True
        assert t1_evidence["verification_status"] == "VERIFIED"

        # Wait for Tier 1 to expire (2.1s)
        time.sleep(2.1)

        # Attempt login after Tier 1 expired: Performed but credentials invalid -> Triggers Tier 2 lockout
        r5 = client.post('/', data={"username": "admin", "password": "bad4"})
        assert r5.status_code == 200

        # Attempt 6 (during Tier 2 lockout): Intercepted at perimeter, duration should be 4s
        r6 = client.post('/', data={"username": "admin", "password": "any"})
        assert r6.status_code == 429
        assert int(r6.headers["Retry-After"]) >= 2  # Tier 2 duration is 4s

        # Verify Tier 2 mitigation record
        history = detector.get_mitigation_history()
        tier2_records = [m for m in history if m["attack_type"] == "BRUTE_FORCE_AUTH" and m["action_taken"] == "LOCKED_OUT"]
        assert len(tier2_records) >= 2
        t2_evidence = tier2_records[-1]["verification_evidence"]
        assert t2_evidence["lockout_tier"] == 2
        assert t2_evidence["lockout_duration_seconds"] == 4
        assert t2_evidence["perimeter_enforced"] is True
        assert t2_evidence["verification_status"] == "VERIFIED"


def test_brute_force_successful_auth_resets_lockout_and_tier(defensive_test_client):
    """Verify legitimate authentication success resets failed attempts, lockout, and tier."""
    client, detector = defensive_test_client
    admin_pass = os.getenv("PORTAL_ADMIN_PASSWORD", "admin123")

    with patch('requests.post'):
        # 2 failures
        client.post('/', data={"username": "admin", "password": "bad1"})
        client.post('/', data={"username": "admin", "password": "bad2"})
        assert len(detector.failed_logins.get("127.0.0.1", [])) == 2

        # Successful login
        success_res = client.post('/', data={"username": "admin", "password": admin_pass})
        assert success_res.status_code == 200
        assert b"Login successful" in success_res.data
        assert "127.0.0.1" not in detector.failed_logins

        # Subsequent failure starts from count 1 and does not lock out
        r_after = client.post('/', data={"username": "admin", "password": "bad3"})
        assert r_after.status_code == 200
        assert len(detector.failed_logins.get("127.0.0.1", [])) == 1


# ==============================================================================
# 2. Directory-Fuzzing Active Throttling
# ==============================================================================

def test_directory_fuzzing_throttling_quarantines_ip_and_blocks_subsequent_requests(defensive_test_client):
    """
    Verify directory-fuzzing throttling:
      - 5 distinct 404 path probes trigger threshold detection and active throttling.
      - Subsequent requests from that IP (even to valid endpoints like GET /) are blocked with HTTP 429.
      - Mitigation record contains empirical evidence of quarantine.
    """
    client, detector = defensive_test_client
    fuzzing_ip = "192.168.31.200"

    with patch('requests.post'):
        # Send 4 distinct 404 probes directly to record_not_found
        for i in range(1, 5):
            res = detector.record_not_found(
                source_ip=fuzzing_ip,
                path=f"/fuzz_probe_{i}",
                status_code=404
            )
            assert res is None  # Below threshold

        # 5th distinct probe: reaches threshold -> triggers throttling
        evt5 = detector.record_not_found(
            source_ip=fuzzing_ip,
            path="/fuzz_probe_5",
            status_code=404
        )
        assert evt5 is not None
        assert evt5["signature"] == "DIR_FUZZ"
        assert evt5["metadata"]["trigger"] == "threshold_exceeded"

        # Verify throttling is active
        is_throttled, rem, tier = detector.fuzz_tracker.is_throttled(fuzzing_ip)
        assert is_throttled is True
        assert rem > 0
        assert tier == 1

        # Subsequent HTTP request from that IP is blocked at WAF perimeter
        blocked_resp = detector.inspect_and_filter(
            source_ip=fuzzing_ip,
            path="/"
        )
        assert blocked_resp is not None
        assert blocked_resp.status_code == 429
        assert "Retry-After" in blocked_resp.headers
        assert b"quarantined due to directory fuzzing" in blocked_resp.data

        # Verify structured mitigation records (trigger and perimeter enforcement)
        history = detector.get_mitigation_history()
        fuzz_mitigations = [m for m in history if m["attack_type"] == "DIR_FUZZ" and m["action_taken"] == "THROTTLED"]
        assert len(fuzz_mitigations) >= 2

        # Trigger record from record_not_found
        trigger_rec = fuzz_mitigations[0]
        assert trigger_rec["source"] == fuzzing_ip
        assert trigger_rec["outcome"] == "ENFORCED"
        assert trigger_rec["verification_evidence"]["distinct_count"] == 5
        assert trigger_rec["verification_evidence"]["verification_status"] == "VERIFIED"

        # Perimeter enforcement record from inspect_and_filter
        enforce_rec = fuzz_mitigations[-1]
        assert enforce_rec["source"] == fuzzing_ip
        assert enforce_rec["outcome"] == "BLOCKED"
        assert enforce_rec["verification_evidence"]["status_code"] == 429
        assert enforce_rec["verification_evidence"]["perimeter_enforced"] is True
        assert enforce_rec["verification_evidence"]["verification_status"] == "VERIFIED"


def test_recon_scanner_user_agent_quarantine(defensive_test_client):
    """Verify reconnaissance scanner User-Agent triggers immediate throttle and perimeter rejection."""
    client, detector = defensive_test_client
    scanner_ip = "192.168.31.205"

    with patch('requests.post'):
        # Scanner UA in 404 probe triggers immediate throttling
        evt = detector.record_not_found(
            source_ip=scanner_ip,
            path="/api/test",
            headers={"User-Agent": "gobuster/3.1.0"}
        )
        assert evt is not None
        assert evt["signature"] == "DIR_FUZZ"

        # IP is now throttled
        is_throttled, rem, _ = detector.fuzz_tracker.is_throttled(scanner_ip)
        assert is_throttled is True

        # Subsequent normal request is blocked
        resp = detector.inspect_and_filter(source_ip=scanner_ip, path="/")
        assert resp is not None
        assert resp.status_code == 429


# ==============================================================================
# 3. WAF Rejection & Structured Mitigation Evidence
# ==============================================================================

def test_waf_rejection_structured_mitigation_evidence(defensive_test_client):
    """
    Verify WAF rejection:
      - Intercepts SQL injection at perimeter with HTTP 400.
      - Dispatches authenticated SOC event with correlated mitigation_action_id.
      - Writes structured mitigation record to disk ledger and memory with empirical verification evidence.
    """
    client, detector = defensive_test_client

    with patch('requests.post') as mock_post:
        mock_post.return_value.status_code = 200
        mock_post.return_value.json.return_value = {"status": "success"}

        resp = client.get("/?id=1%20UNION%20SELECT%20null,username,password%20FROM%20users--")
        assert resp.status_code == 400
        assert b"WAF Protection Active" in resp.data

        # SOC event verification
        mock_post.assert_called_once()
        soc_payload = mock_post.call_args[1]["json"]
        assert soc_payload["signature"] == "SQL_INJECTION"
        action_id = soc_payload["metadata"]["mitigation_action_id"]
        assert action_id.startswith("ACT-MIT-")

        # In-memory mitigation ledger verification
        history = detector.get_mitigation_history()
        matching = [m for m in history if m["action_id"] == action_id]
        assert len(matching) == 1
        record = matching[0]

        assert record["attack_type"] == "SQL_INJECTION"
        assert record["action_taken"] == "BLOCKED"
        assert record["outcome"] == "BLOCKED"
        assert "T" in record["timestamp"]  # ISO-8601
        evidence = record["verification_evidence"]
        assert evidence["status_code"] == 400
        assert evidence["rule"] == "SQLI_PATTERN_DETECTED"
        assert evidence["perimeter_enforced"] is True
        assert evidence["verification_status"] == "VERIFIED"


def test_cmdi_and_path_traversal_mitigation_evidence(defensive_test_client):
    """Verify Command Injection and Path Traversal produce structured mitigation evidence."""
    client, detector = defensive_test_client

    with patch('requests.post') as mock_post:
        mock_post.return_value.status_code = 200
        mock_post.return_value.json.return_value = {"status": "success"}

        # Command Injection
        r_cmdi = client.get("/?view=test;whoami")
        assert r_cmdi.status_code == 400
        cmdi_record = detector.mitigation_history[-1]
        assert cmdi_record["attack_type"] == "COMMAND_INJECTION"
        assert cmdi_record["verification_evidence"]["verification_status"] == "VERIFIED"

        # Path Traversal
        r_trav = client.get("/?file=../../../../etc/shadow")
        assert r_trav.status_code == 400
        trav_record = detector.mitigation_history[-1]
        assert trav_record["attack_type"] == "PATH_TRAVERSAL"
        assert trav_record["verification_evidence"]["verification_status"] == "VERIFIED"


# ==============================================================================
# 4. PORT_SCAN Mitigation Pipeline
# ==============================================================================

def test_port_scan_mitigation_pipeline_records_aggregated_evidence(defensive_test_client):
    """Verify aggregated PORT_SCAN pipeline emits single alert and records mitigation evidence."""
    _, detector = defensive_test_client
    scanner_ip = "192.168.31.250"
    ports = [21, 22, 23, 25, 80, 443, 3306, 8080]

    with patch('requests.post') as mock_post:
        mock_post.return_value.status_code = 200
        mock_post.return_value.json.return_value = {"status": "success"}

        event = detector.record_port_scan(
            source_ip=scanner_ip,
            distinct_ports=ports,
            window_seconds=10.0,
            duration_seconds=1.2
        )
        assert event["signature"] == "PORT_SCAN"
        assert event["event_type"] == "PORT_SCAN"
        assert event["metadata"]["mitre_technique"] == "T1046"

        # Check correlated mitigation record
        history = detector.get_mitigation_history()
        port_scan_records = [m for m in history if m["attack_type"] == "PORT_SCAN"]
        assert len(port_scan_records) == 1
        ps_record = port_scan_records[0]

        assert ps_record["action_taken"] == "AGGREGATED_AND_MONITORED"
        assert ps_record["outcome"] == "TRACKED_AND_REPORTED"
        ev = ps_record["verification_evidence"]
        assert ev["distinct_ports_count"] == 8
        assert ev["mitre_technique"] == "T1046"
        assert ev["deduplicated"] is True
        assert ev["verification_status"] == "VERIFIED"


# ==============================================================================
# 5. Safe Defensive Policy: Whitelist, Expiry, and Rollback
# ==============================================================================

def test_safe_defensive_policy_whitelist_protection():
    """Verify SafeDefensivePolicy strictly preserves whitelist invariants."""
    policy = SafeDefensivePolicy()

    # Localhost and server IPs cannot be blocked
    assert policy.is_whitelisted("127.0.0.1") is True
    assert policy.is_whitelisted("localhost") is True
    assert policy.is_whitelisted(os.getenv("CN_SERVER_IP", "192.168.31.91")) is True

    allowed, reason = policy.can_block("127.0.0.1")
    assert allowed is False
    assert "whitelisted" in reason

    # Attempting to apply block on whitelisted IP is refused
    assert policy.apply_block("127.0.0.1", "test", "TEST") is None

    # External IP is allowed to be blocked
    ext_ip = "192.168.31.222"
    allowed, _ = policy.can_block(ext_ip)
    assert allowed is True


def test_safe_defensive_policy_finite_expiry_and_auto_purge():
    """Verify blocks have strict finite expiry and auto-expire cleanly."""
    policy = SafeDefensivePolicy()
    ip = "192.168.31.223"

    # Block for 1 second
    record = policy.apply_block(ip, reason="Automated quarantine test", attack_type="SCAN", duration_seconds=1)
    assert record is not None
    assert record["action_id"].startswith("ACT-MIT-")

    # Immediately blocked
    is_blk, rem = policy.is_blocked(ip)
    assert is_blk is True
    assert rem >= 1

    # Wait for expiration
    time.sleep(1.1)

    # Automatically expired
    is_blk2, rem2 = policy.is_blocked(ip)
    assert is_blk2 is False
    assert rem2 == 0

    # Auto-expiration record logged in history
    exp_records = [h for h in policy.history if h["action_taken"] == "AUTO_EXPIRE"]
    assert len(exp_records) == 1
    assert exp_records[0]["outcome"] == "EXPIRED"


def test_safe_defensive_policy_administrative_and_emergency_rollback():
    """Verify administrative rollback releases target IP and emergency rollback releases all IPs."""
    policy = SafeDefensivePolicy()
    ip1 = "192.168.31.224"
    ip2 = "192.168.31.225"

    policy.apply_block(ip1, reason="Test", attack_type="DIR_FUZZ", duration_seconds=300)
    policy.apply_block(ip2, reason="Test", attack_type="DIR_FUZZ", duration_seconds=300)

    # Administrative rollback for ip1
    rollback_record = policy.rollback_block(ip1, reason="admin_investigation_cleared")
    assert rollback_record is not None
    assert rollback_record["action_taken"] == "ROLLBACK"
    assert rollback_record["outcome"] == "RELEASED"

    # ip1 is unblocked, ip2 remains blocked
    assert policy.is_blocked(ip1)[0] is False
    assert policy.is_blocked(ip2)[0] is True

    # Emergency global rollback
    revoked = policy.rollback_all(reason="incident_commander_release")
    assert revoked == 1
    assert policy.is_blocked(ip2)[0] is False
    assert len(policy.get_active_blocks()) == 0


def test_reset_ip_defenses_full_integration(defensive_test_client):
    """Verify detector.reset_ip_defenses simultaneously releases lockout, throttle, and policy blocks."""
    _, detector = defensive_test_client
    ip = "192.168.31.230"

    # Set up active lockout and throttle
    detector.waf.brute_force_protector.lockouts[ip] = time.time() + 300
    detector.waf.brute_force_protector.lockout_tiers[ip] = 2
    detector.fuzz_tracker.throttles[ip] = time.time() + 300
    detector.defense_policy.apply_block(ip, "Test", "ATTACK", duration_seconds=300)

    active = detector.get_active_defenses()
    assert any(a["ip"] == ip for a in active["active_lockouts"])
    assert any(a["ip"] == ip for a in active["active_throttles"])
    assert any(a["ip"] == ip for a in active["active_policy_blocks"])

    # Reset all defenses for IP
    mit_record = detector.reset_ip_defenses(ip, reason="manual_secops_override")
    assert mit_record["action_taken"] == "ROLLBACK"
    assert mit_record["outcome"] == "RELEASED"

    # Verify all defenses are released
    active_after = detector.get_active_defenses()
    assert not any(a["ip"] == ip for a in active_after["active_lockouts"])
    assert not any(a["ip"] == ip for a in active_after["active_throttles"])
    assert not any(a["ip"] == ip for a in active_after["active_policy_blocks"])


# ==============================================================================
# 6. Mitigation Disk Log Persistence
# ==============================================================================

def test_mitigations_log_file_persistence_and_schema(defensive_test_client):
    """Verify all mitigation records written to logs/mitigations.log match the evidence schema."""
    _, detector = defensive_test_client

    # Write a test mitigation record
    rec = detector.record_mitigation(
        attack_type="SQL_INJECTION",
        source="192.168.31.240",
        action_taken="BLOCKED",
        outcome="BLOCKED",
        verification_evidence={
            "status_code": 400,
            "rule": "SQLI_PATTERN_DETECTED",
            "perimeter_enforced": True,
            "verification_status": "VERIFIED"
        }
    )

    mitigation_file = detector.logger.mitigation_log_file
    assert mitigation_file.exists()

    with open(mitigation_file, "r", encoding="utf-8") as f:
        lines = [line.strip() for line in f if line.strip()]

    # Verify last line matches schema
    last_record = json.loads(lines[-1])
    required_keys = {
        "action_id", "attack_type", "source", "target", "action_taken",
        "timestamp", "outcome", "verification_evidence"
    }
    for key in required_keys:
        assert key in last_record, f"Missing required key '{key}' in mitigation record"

    assert last_record["verification_evidence"]["verification_status"] == "VERIFIED"
    assert last_record["action_id"].startswith("ACT-MIT-")
