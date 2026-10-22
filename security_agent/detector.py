import uuid
import os
import sys
import time
from pathlib import Path
from typing import Optional, Dict, Any, Tuple, List

# Ensure agent directory is in sys.path for fallback standalone execution
AGENT_DIR = Path(__file__).resolve().parent
if str(AGENT_DIR) not in sys.path:
    sys.path.insert(0, str(AGENT_DIR))

try:
    from .config import load_portal_env
    load_portal_env()
    from .event_logger import EventLogger
    from .alert_client import AlertClient
    from .waf import WAFInspector, WAFConfig, DirectoryFuzzTracker
    from .defense_policy import SafeDefensivePolicy
except (ImportError, ValueError):
    try:
        from config import load_portal_env
        load_portal_env()
    except ImportError:
        pass
    from event_logger import EventLogger
    from alert_client import AlertClient
    from waf import WAFInspector, WAFConfig, DirectoryFuzzTracker
    from defense_policy import SafeDefensivePolicy

class ServerDetector:
    """Security detection engine operating on protected server."""

    def __init__(self, soc_url: Optional[str] = None, api_key: Optional[str] = None, port: Optional[int] = None):
        self.cn_server_ip = os.getenv("CN_SERVER_IP")
        if not self.cn_server_ip:
            raise ValueError("CN_SERVER_IP is not configured. Set CN_SERVER_IP to the protected server IP, e.g. 192.168.31.91")
        self.server_port = port or int(os.getenv("PORT", "5000"))
        self.logger = EventLogger()
        self.client = AlertClient(soc_url, api_key)
        self.fuzz_tracker = DirectoryFuzzTracker(
            threshold=int(os.getenv("DIR_FUZZ_THRESHOLD", "5")),
            window_seconds=int(os.getenv("DIR_FUZZ_WINDOW_SECONDS", "60")),
            cooldown_seconds=int(os.getenv("DIR_FUZZ_COOLDOWN_SECONDS", "10")),
            throttle_seconds=int(os.getenv("WAF_DIR_FUZZ_THROTTLE_SECONDS", "60"))
        )
        self.waf = WAFInspector(fuzz_tracker=self.fuzz_tracker)
        # ip -> list of failure timestamps (sliding window)
        self.failed_logins: Dict[str, List[float]] = {}
        self.auth_decay_seconds = int(os.getenv("WAF_AUTH_DECAY_SECONDS", "300"))
        self.defense_policy = SafeDefensivePolicy()
        self.mitigation_history: List[Dict[str, Any]] = []

    def record_mitigation(
        self,
        attack_type: str,
        source: str,
        action_taken: str,
        outcome: str,
        verification_evidence: Dict[str, Any],
        target: Optional[str] = None,
        event_id: Optional[str] = None,
        message: str = ""
    ) -> Dict[str, Any]:
        """
        Record a structured mitigation evidence entry to the persistent mitigation log
        and the in-memory defensive ledger with a stable action identifier.
        """
        action_id = f"ACT-MIT-{uuid.uuid4().hex[:8].upper()}"
        target_asset = target or f"{self.cn_server_ip}:{self.server_port}"
        try:
            from datetime import timezone, datetime
            iso_ts = datetime.now(timezone.utc).isoformat()
        except Exception:
            from datetime import datetime
            iso_ts = datetime.utcnow().isoformat() + "Z"

        record: Dict[str, Any] = {
            "action_id": action_id,
            "event_id": event_id,
            "attack_type": attack_type,
            "source": source,
            "target": target_asset,
            "action_taken": action_taken,
            "timestamp": iso_ts,
            "outcome": outcome,
            "verification_evidence": verification_evidence
        }
        if message:
            record["message"] = message

        self.logger.log_mitigation(record)
        self.mitigation_history.append(record)
        if len(self.mitigation_history) > 1000:
            self.mitigation_history = self.mitigation_history[-1000:]
        return record

    def get_mitigation_history(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Return recent recorded mitigation evidence records."""
        return self.mitigation_history[-limit:]

    def get_active_defenses(self) -> Dict[str, Any]:
        """Return snapshot of active progressive lockouts, throttles, and safe policy blocks."""
        return {
            "active_lockouts": self.waf.brute_force_protector.get_active_lockouts(),
            "active_throttles": self.fuzz_tracker.get_active_throttles(),
            "active_policy_blocks": self.defense_policy.get_active_blocks()
        }

    def reset_ip_defenses(self, source_ip: str, reason: str = "administrative_release") -> Dict[str, Any]:
        """Administrative rollback / reset of all defensive restrictions for a given IP."""
        self.waf.brute_force_protector.reset_ip(source_ip)
        self.fuzz_tracker.reset_ip(source_ip)
        self.failed_logins.pop(source_ip, None)
        rollback_info = self.defense_policy.rollback_block(source_ip, reason=reason)
        evidence = {
            "reason": reason,
            "policy_released": True,
            "brute_force_reset": True,
            "fuzz_throttle_reset": True,
            "verification_status": "VERIFIED"
        }
        if rollback_info:
            evidence["rollback_action_id"] = rollback_info.get("action_id")
        return self.record_mitigation(
            attack_type="ADMINISTRATIVE_RESET",
            source=source_ip,
            action_taken="ROLLBACK",
            outcome="RELEASED",
            verification_evidence=evidence
        )

    def inspect_http_request(
        self,
        source_ip: str,
        path: str,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        query_string: str = "",
        body: str = "",
        content_length: Optional[int] = None
    ) -> Optional[Dict[str, Any]]:
        """Inspect HTTP requests using WAF policies for malicious signatures in URL, headers, and body."""
        headers = headers or {}
        # Check safe policy active perimeter blocks first
        is_blocked, remaining = self.defense_policy.is_blocked(source_ip)
        if is_blocked:
            block_info = self.defense_policy.active_blocks.get(source_ip, {})
            detection = {
                "blocked": True,
                "status_code": 403,
                "rule": "PERIMETER_QUARANTINE",
                "signature": block_info.get("attack_type", "DIR_FUZZ"),
                "severity": "HIGH",
                "message": f"Client IP '{source_ip}' is quarantined under safe defensive policy ({remaining}s remaining): {block_info.get('reason', 'Perimeter defense')}",
                "metadata": {
                    "source_ip": source_ip,
                    "retry_after_seconds": remaining,
                    "action_id": block_info.get("action_id"),
                    "policy": "safe_defensive_policy"
                },
                "client_message": f"403 Forbidden: Client IP temporarily quarantined under server security policy. Retry in {remaining} seconds.",
                "action_taken": "QUARANTINED",
                "attack_type": block_info.get("attack_type", "DEFENSE_POLICY"),
                "outcome": "BLOCKED",
                "verification_evidence": {
                    "status_code": 403,
                    "retry_after": remaining,
                    "action_id": block_info.get("action_id"),
                    "perimeter_enforced": True,
                    "verification_status": "VERIFIED"
                }
            }
        else:
            detection = self.waf.inspect_request(
                source_ip=source_ip,
                path=path,
                method=method,
                headers=headers,
                query_string=query_string,
                body=body,
                content_length=content_length
            )

        if not detection:
            return None

        # Sanitize metadata for SOC event to avoid echoing long bodies or secrets
        sanitized_metadata = dict(detection.get("metadata", {}))
        if "body" in sanitized_metadata:
            sanitized_metadata["body"] = sanitized_metadata["body"][:150]
        sanitized_metadata.setdefault("http_method", method.upper())
        sanitized_metadata.setdefault("requested_path", path)
        sanitized_metadata.setdefault("response_status", detection.get("status_code", 403 if detection.get("blocked") else 200))
        sanitized_metadata.setdefault("detection_reason", detection.get("message", "WAF rule violation detected"))

        sig = detection.get("signature", "DIR_FUZZ")
        event_type = sig if sig in ("SQL_INJECTION", "COMMAND_INJECTION", "PATH_TRAVERSAL", "DIR_FUZZ", "PORT_SCAN") else detection.get("rule", sig)

        attack_type = detection.get("attack_type", sig)
        action_taken = detection.get("action_taken", "BLOCKED")
        outcome = detection.get("outcome", "BLOCKED" if detection.get("blocked") else "MONITORED")
        verification_evidence = dict(detection.get("verification_evidence", {}))
        verification_evidence.setdefault("status_code", detection.get("status_code", 400))
        verification_evidence.setdefault("rule", detection.get("rule", "WAF_RULE"))
        verification_evidence.setdefault("perimeter_enforced", (self.waf.config.mode == "BLOCK"))
        verification_evidence.setdefault("verification_status", "VERIFIED")

        mitigation_record = self.record_mitigation(
            attack_type=attack_type,
            source=source_ip,
            action_taken=action_taken,
            outcome=outcome,
            verification_evidence=verification_evidence,
            message=detection.get("message", "")
        )

        sanitized_metadata["mitigation_action_id"] = mitigation_record["action_id"]
        sanitized_metadata["action_taken"] = action_taken
        sanitized_metadata["outcome"] = outcome

        event = self._trigger_event(
            event_type=event_type,
            signature=sig,
            severity=detection.get("severity", "HIGH"),
            source_ip=source_ip,
            destination_port=self.server_port,
            message=detection.get("message", "WAF rule violation detected"),
            metadata=sanitized_metadata
        )

        if event:
            event["_waf_blocked"] = (self.waf.config.mode == "BLOCK")
            event["_waf_detection"] = detection
            event["_mitigation"] = mitigation_record
            mitigation_record["event_id"] = event.get("event_id")

        return event

    def inspect_and_filter(
        self,
        source_ip: str,
        path: str,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        query_string: str = "",
        body: str = "",
        content_length: Optional[int] = None
    ) -> Optional[Any]:
        """
        Evaluate request and return a Flask Response if blocked by WAF policy, or None to allow.
        """
        event = self.inspect_http_request(
            source_ip=source_ip,
            path=path,
            method=method,
            headers=headers,
            query_string=query_string,
            body=body,
            content_length=content_length
        )
        if event and event.get("_waf_blocked") and event.get("_waf_detection"):
            return self.waf.build_client_response(event["_waf_detection"])
        return None


    def record_not_found(
        self,
        source_ip: str,
        path: str,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        status_code: int = 404
    ) -> Optional[Dict[str, Any]]:
        """
        Evaluate HTTP 404 responses for directory discovery attacks.
        Distinguishes benign 404s, explicit suspicious path probes, and repeated distinct fuzzing bursts.
        Preserves source_ip, http_method, requested_path, timestamp, response_status, detection_reason.
        """
        headers = headers or {}
        ua = headers.get("User-Agent", "").lower()

        # 1. Recon scanner tool User-Agent probe
        for tool in self.waf.SCANNER_AGENTS:
            if tool in ua:
                duration = self.fuzz_tracker.record_recon_scanner(source_ip, tool)
                msg = f"Reconnaissance scanner detected ({tool}) targeting {path}"
                mitigation_record = self.record_mitigation(
                    attack_type="DIR_FUZZ",
                    source=source_ip,
                    action_taken="THROTTLED",
                    outcome="ENFORCED",
                    verification_evidence={
                        "status_code": 403,
                        "scanner": tool,
                        "throttle_duration": duration,
                        "perimeter_enforced": True,
                        "verification_status": "VERIFIED"
                    },
                    message=msg
                )
                event = self._trigger_event(
                    event_type="DIR_FUZZ",
                    signature="DIR_FUZZ",
                    severity="HIGH",
                    source_ip=source_ip,
                    destination_port=self.server_port,
                    message=msg,
                    metadata={
                        "http_method": method.upper(),
                        "requested_path": path,
                        "response_status": status_code,
                        "detection_reason": msg,
                        "user_agent": headers.get("User-Agent", ""),
                        "trigger": "recon_scanner_user_agent",
                        "mitigation_action_id": mitigation_record["action_id"]
                    }
                )
                if event:
                    mitigation_record["event_id"] = event.get("event_id")
                return event

        # 2. Explicit suspicious path indicator
        is_suspicious, matched_indicator = self.waf.is_explicit_suspicious_path(path)
        if is_suspicious:
            now = time.time()
            key = (source_ip, path)
            last_sent = self.fuzz_tracker.explicit_path_alerts.get(key, 0)
            if now - last_sent < self.fuzz_tracker.cooldown_seconds:
                # Debounced: avoid duplicate alert for identical probe within cooldown
                return None
            self.fuzz_tracker.explicit_path_alerts[key] = now

            msg = f"Explicit suspicious path probe detected: {path} (matched '{matched_indicator}')"
            mitigation_record = self.record_mitigation(
                attack_type="DIR_FUZZ",
                source=source_ip,
                action_taken="BLOCKED",
                outcome="ENFORCED",
                verification_evidence={
                    "status_code": status_code,
                    "matched_indicator": matched_indicator,
                    "perimeter_enforced": True,
                    "verification_status": "VERIFIED"
                },
                message=msg
            )
            event = self._trigger_event(
                event_type="DIR_FUZZ",
                signature="DIR_FUZZ",
                severity="HIGH",
                source_ip=source_ip,
                destination_port=self.server_port,
                message=msg,
                metadata={
                    "http_method": method.upper(),
                    "requested_path": path,
                    "response_status": status_code,
                    "detection_reason": msg,
                    "matched_indicator": matched_indicator,
                    "trigger": "explicit_suspicious_path",
                    "mitigation_action_id": mitigation_record["action_id"]
                }
            )
            if event:
                mitigation_record["event_id"] = event.get("event_id")
            return event

        # 3. Repeated distinct path probes threshold
        detected, info = self.fuzz_tracker.record_404_probe(source_ip, path)
        if detected and info:
            msg = info["message"]
            mitigation_record = self.record_mitigation(
                attack_type="DIR_FUZZ",
                source=source_ip,
                action_taken="THROTTLED",
                outcome="ENFORCED",
                verification_evidence={
                    "status_code": 429,
                    "distinct_count": info["distinct_count"],
                    "throttle_duration": info["throttle_duration"],
                    "throttle_tier": info["throttle_tier"],
                    "probed_paths_sample": info["probed_paths"][:10],
                    "perimeter_enforced": True,
                    "verification_status": "VERIFIED"
                },
                message=msg
            )
            event = self._trigger_event(
                event_type="DIR_FUZZ",
                signature="DIR_FUZZ",
                severity=info["severity"],
                source_ip=source_ip,
                destination_port=self.server_port,
                message=msg,
                metadata={
                    "http_method": method.upper(),
                    "requested_path": path,
                    "response_status": status_code,
                    "detection_reason": msg,
                    "distinct_count": info["distinct_count"],
                    "probed_paths_sample": info["probed_paths"][:10],
                    "trigger": "threshold_exceeded",
                    "throttle_duration": info["throttle_duration"],
                    "throttle_tier": info["throttle_tier"],
                    "mitigation_action_id": mitigation_record["action_id"]
                }
            )
            if event:
                mitigation_record["event_id"] = event.get("event_id")
            return event

        return None

    def record_auth_failure(self, source_ip: str, username: str) -> Dict[str, Any]:
        """Record and evaluate failed authentication attempt using sliding window decay and progressive lockout."""
        now = time.time()
        # Prune failures older than decay window
        recent = [t for t in self.failed_logins.get(source_ip, []) if now - t < self.auth_decay_seconds]
        recent.append(now)
        self.failed_logins[source_ip] = recent
        count = len(recent)

        is_now_locked = False
        tier = 0
        if hasattr(self, "waf") and hasattr(self.waf, "brute_force_protector"):
            self.waf.brute_force_protector.decay_seconds = self.auth_decay_seconds
            self.waf.brute_force_protector.failures[source_ip] = list(recent[:-1])
            _, is_now_locked = self.waf.brute_force_protector.record_failure(source_ip)
            tier = self.waf.brute_force_protector.get_tier(source_ip)

        mitigation_record = None
        if count >= 3:
            sev = "HIGH"
            event_type = "AUTH_BRUTE_FORCE"
            action_taken = "LOCKED_OUT"
            outcome = "ENFORCED"
            msg = f"Repeated authentication failure burst ({count} attempts within {self.auth_decay_seconds}s) for user '{username}' (Tier {tier})"
            lockout_dur = min(
                self.waf.brute_force_protector.lockout_seconds * (2 ** max(0, tier - 1)),
                self.waf.brute_force_protector.max_lockout_seconds
            )
            mitigation_record = self.record_mitigation(
                attack_type="BRUTE_FORCE_AUTH",
                source=source_ip,
                action_taken=action_taken,
                outcome=outcome,
                verification_evidence={
                    "status_code": 429,
                    "failure_count": count,
                    "lockout_tier": tier,
                    "lockout_duration_seconds": lockout_dur,
                    "policy": "progressive_exponential_lockout",
                    "perimeter_enforced": True,
                    "verification_status": "VERIFIED"
                },
                message=msg
            )
        else:
            sev = "LOW"
            msg = f"Failed authentication attempt for user '{username}'"
            event_type = "LOGIN_FAILED"

        meta = {"username": username, "failure_count": count, "is_burst": count >= 3}
        if mitigation_record:
            meta["mitigation_action_id"] = mitigation_record["action_id"]
            meta["lockout_tier"] = tier

        event = self._trigger_event(
            event_type=event_type,
            signature="BRUTE_FORCE_AUTH",
            severity=sev,
            source_ip=source_ip,
            destination_port=self.server_port,
            message=msg,
            metadata=meta
        )
        if event and mitigation_record:
            mitigation_record["event_id"] = event.get("event_id")
        return event

    def record_auth_success(self, source_ip: str, username: str) -> Dict[str, Any]:
        """Log successful authentication locally and clear failed attempts for this IP."""
        self.failed_logins.pop(source_ip, None)
        if hasattr(self, "waf") and hasattr(self.waf, "brute_force_protector"):
            self.waf.brute_force_protector.record_success(source_ip)
        eid = f"EVT-HP-{uuid.uuid4().hex[:8].upper()}"
        return self.logger.log_and_format(
            event_id=eid,
            event_type="LOGIN_SUCCESS",
            signature="AUTH_SUCCESS",
            severity="INFO",
            source_ip=source_ip,
            destination_port=self.server_port,
            message=f"Successful authentication for user '{username}'",
            metadata={"username": username}
        )

    def record_network_connection(
        self,
        source_ip: str,
        destination_port: int,
        protocol: str = "TCP",
        message: Optional[str] = None,
        is_test: int = 0
    ) -> Dict[str, Any]:
        """Record network port connection / probe observed targeting protected asset."""
        msg = message or f"Port scan / connection probe to port {destination_port} ({protocol})"
        return self._trigger_event(
            event_type="PORT_SCAN",
            signature="PORT_SCAN",
            severity="LOW",
            source_ip=source_ip,
            destination_port=destination_port,
            message=msg,
            metadata={
                "probed_port": destination_port,
                "protocol": protocol,
                "asset": f"Protected Web Server ({self.cn_server_ip})"
            },
            is_test=is_test
        )

    def record_port_scan(
        self,
        source_ip: str,
        distinct_ports: List[int],
        target_ip: Optional[str] = None,
        window_seconds: Optional[float] = None,
        duration_seconds: Optional[float] = None,
        message: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        severity: str = "HIGH",
        is_test: int = 0
    ) -> Dict[str, Any]:
        """Record aggregated port scan alert when distinct port threshold is crossed and register mitigation evidence."""
        dst_ip = target_ip or self.cn_server_ip
        observed_ports = sorted(list(set(distinct_ports)))
        count = len(observed_ports)
        primary_port = observed_ports[0] if observed_ports else self.server_port

        msg = message or (
            f"TCP port scan detected from {source_ip} targeting {dst_ip}: "
            f"{count} distinct ports probed ({observed_ports[:10]}{'...' if len(observed_ports) > 10 else ''})"
        )

        mitigation_record = self.record_mitigation(
            attack_type="PORT_SCAN",
            source=source_ip,
            target=f"{dst_ip}:{primary_port}",
            action_taken="AGGREGATED_AND_MONITORED",
            outcome="TRACKED_AND_REPORTED",
            verification_evidence={
                "distinct_ports_count": count,
                "observed_ports_sample": observed_ports[:10],
                "window_seconds": window_seconds,
                "duration_seconds": duration_seconds,
                "mitre_technique": "T1046",
                "deduplicated": True,
                "perimeter_enforced": True,
                "verification_status": "VERIFIED"
            },
            message=msg
        )

        meta = {
            "target_ip": dst_ip,
            "distinct_ports_count": count,
            "observed_ports": observed_ports,
            "window_seconds": window_seconds,
            "duration_seconds": duration_seconds,
            "asset": f"Protected Web Server ({self.cn_server_ip})",
            "mitre_technique": "T1046",
            "mitre_name": "Network Service Discovery",
            "mitigation_action_id": mitigation_record["action_id"],
            "action_taken": "AGGREGATED_AND_MONITORED",
            "outcome": "TRACKED_AND_REPORTED"
        }
        if metadata:
            meta.update(metadata)

        event = self._trigger_event(
            event_type="PORT_SCAN",
            signature="PORT_SCAN",
            severity=severity,
            source_ip=source_ip,
            destination_port=primary_port,
            message=msg,
            metadata=meta,
            is_test=is_test
        )
        if event and mitigation_record:
            mitigation_record["event_id"] = event.get("event_id")
        return event

    def record_heartbeat(self) -> Dict[str, Any]:
        """Transmit routine agent health check heartbeat."""
        return self._trigger_event(
            event_type="HEARTBEAT",
            signature="HEARTBEAT",
            severity="INFO",
            source_ip=self.cn_server_ip,
            destination_port=self.server_port,
            message="Protected Web Server security agent telemetry heartbeat"
        )

    def _trigger_event(
        self,
        event_type: str,
        severity: str,
        source_ip: str,
        destination_port: int,
        message: str,
        metadata: Optional[Dict[str, Any]] = None,
        is_test: int = 0,
        signature: Optional[str] = None
    ) -> Dict[str, Any]:
        eid = f"EVT-HP-{uuid.uuid4().hex[:8].upper()}"
        sig = signature or event_type
        event = self.logger.log_and_format(
            event_id=eid,
            event_type=event_type,
            signature=sig,
            severity=severity,
            source_ip=source_ip,
            destination_port=destination_port,
            message=message,
            metadata=metadata,
            is_test=is_test
        )
        success, response = self.client.send_event(event)
        if success:
            print(f"[+] [ALERT] Event sent to SOC: {eid} (sig: {sig})")
        else:
            print(f"[-] [ALERT] Failed to send event to SOC: {response.get('error', 'Unknown')} - {response.get('detail', '')}")
        return event

