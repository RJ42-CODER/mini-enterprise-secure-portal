import uuid
import os
import time
from typing import Optional, Dict, Any, Tuple, List
try:
    from .config import load_portal_env
    load_portal_env()
    from .event_logger import EventLogger
    from .alert_client import AlertClient
    from .waf import WAFInspector, WAFConfig
except ImportError:
    try:
        from config import load_portal_env
        load_portal_env()
    except ImportError:
        pass
    from event_logger import EventLogger
    from alert_client import AlertClient
    from waf import WAFInspector, WAFConfig

class ServerDetector:
    """Security detection engine operating on protected server."""

    def __init__(self, soc_url: Optional[str] = None, api_key: Optional[str] = None, port: Optional[int] = None):
        self.cn_server_ip = os.getenv("CN_SERVER_IP")
        if not self.cn_server_ip:
            raise ValueError("CN_SERVER_IP is not configured. Set CN_SERVER_IP to the protected server IP, e.g. 192.168.31.91")
        self.server_port = port or int(os.getenv("PORT", "5000"))
        self.logger = EventLogger()
        self.client = AlertClient(soc_url, api_key)
        self.waf = WAFInspector()
        # ip -> list of failure timestamps (sliding window)
        self.failed_logins: Dict[str, List[float]] = {}
        self.auth_decay_seconds = 300  # 5 minute sliding decay window

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

        sig = detection.get("signature", "DIR_FUZZ")
        event_type = sig if sig in ("SQL_INJECTION", "COMMAND_INJECTION", "PATH_TRAVERSAL", "DIR_FUZZ", "PORT_SCAN") else detection.get("rule", sig)

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

    def record_auth_failure(self, source_ip: str, username: str) -> Dict[str, Any]:
        """Record and evaluate failed authentication attempt using sliding window decay."""
        now = time.time()
        # Prune failures older than decay window
        recent = [t for t in self.failed_logins.get(source_ip, []) if now - t < self.auth_decay_seconds]
        recent.append(now)
        self.failed_logins[source_ip] = recent
        count = len(recent)

        # Sync failure to WAF brute force protector
        if hasattr(self, "waf") and hasattr(self.waf, "brute_force_protector"):
            self.waf.brute_force_protector.record_failure(source_ip)

        if count >= 3:
            sev = "HIGH"
            msg = f"Repeated authentication failure burst ({count} attempts within {self.auth_decay_seconds}s) for user '{username}'"
            event_type = "AUTH_BRUTE_FORCE"
        else:
            sev = "LOW"
            msg = f"Failed authentication attempt for user '{username}'"
            event_type = "LOGIN_FAILED"

        return self._trigger_event(
            event_type=event_type,
            signature="BRUTE_FORCE_AUTH",
            severity=sev,
            source_ip=source_ip,
            destination_port=self.server_port,
            message=msg,
            metadata={"username": username, "failure_count": count, "is_burst": count >= 3}
        )

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

