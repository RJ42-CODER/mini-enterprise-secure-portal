import os
import json
import time
import threading
import requests
from pathlib import Path
from typing import Dict, Any, Tuple, List, Optional

class AlertClient:
    """
    Transmits security telemetry from protected server to SOC backend.
    Includes persistent offline buffering & retry mechanism to guarantee zero event loss
    if the SOC is temporarily unreachable or undergoing maintenance.
    """
    
    def __init__(self, soc_url: Optional[str] = None, api_key: Optional[str] = None, spool_dir: Optional[str] = None):
        final_soc_url = soc_url or os.getenv("SOC_URL")
        if not final_soc_url:
            raise ValueError("SOC_URL is not configured. Set SOC_URL to the Victus SOC backend, e.g. http://192.168.31.204:5050")
        self.soc_url = final_soc_url.rstrip("/")
        
        # Require explicit token; support both SOC_API_KEY and SOC_AGENT_TOKEN
        self.api_key = api_key or os.getenv("SOC_API_KEY") or os.getenv("SOC_AGENT_TOKEN")
        if not self.api_key:
            raise ValueError("SOC authentication token is not configured. Set SOC_API_KEY or SOC_AGENT_TOKEN in your environment or .env file.")
        
        self.endpoint = os.getenv("SOC_EVENTS_ENDPOINT") or f"{self.soc_url}/api/events"
        
        base_dir = Path(__file__).resolve().parent.parent
        self.spool_dir = Path(spool_dir) if spool_dir else (base_dir / "logs")
        self.spool_dir.mkdir(parents=True, exist_ok=True)
        self.spool_file = self.spool_dir / "event_spool.jsonl"
        self._lock = threading.Lock()

    def validate_payload(self, event_payload: Dict[str, Any]) -> Tuple[bool, str]:
        """Validate payload structure before attempting network delivery."""
        if not isinstance(event_payload, dict):
            return False, "Payload must be a dictionary"
        # If payload has telemetry identifiers, enforce presence of valid source_ip
        if any(k in event_payload for k in ("event_id", "signature", "event_type")):
            source_ip = event_payload.get("source_ip")
            if not source_ip or not isinstance(source_ip, str) or not source_ip.strip():
                return False, "Telemetry event requires a valid non-empty 'source_ip'"
        return True, ""

    def send_event(self, event_payload: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
        """
        Send event over authenticated HTTP API.
        If network fails or SOC is unavailable (5xx/ConnectionError), automatically spools to disk.
        Permanent 4xx errors are reported distinctly without buffering.
        """
        valid, err_msg = self.validate_payload(event_payload)
        if not valid:
            return False, {"error": "ValidationError", "detail": err_msg, "buffered": False}

        # First attempt to flush any previously spooled events
        self._flush_spool_quietly()

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "User-Agent": "HP-Victus-Security-Agent/1.0"
        }
        try:
            response = requests.post(self.endpoint, json=event_payload, headers=headers, timeout=5)
            # Accept HTTP 200 OK, 201 Created, and 202 Accepted
            if response.status_code in (200, 201, 202):
                try:
                    res_body = response.json()
                except Exception:
                    res_body = {"status": "accepted", "status_code": response.status_code, "text": response.text[:200]}
                return True, res_body
            elif response.status_code == 401:
                return False, {"error": "Unauthorized", "detail": "Invalid or missing SOC authentication token (HTTP 401)", "status_code": 401, "buffered": False}
            elif response.status_code == 403:
                return False, {"error": "Forbidden", "detail": "Access forbidden by SOC backend (HTTP 403)", "status_code": 403, "buffered": False}
            elif response.status_code == 404:
                return False, {"error": "NotFound", "detail": f"SOC events route not found at {self.endpoint} (HTTP 404)", "status_code": 404, "buffered": False}
            elif response.status_code in (400, 422):
                err_type = "BadRequest" if response.status_code == 400 else "UnprocessableEntity"
                return False, {"error": err_type, "detail": f"SOC rejected payload (HTTP {response.status_code}): {response.text[:200]}", "status_code": response.status_code, "buffered": False}
            elif response.status_code >= 500:
                # Server side error - buffer for retry
                self._buffer_event(event_payload)
                return False, {"error": f"HTTP {response.status_code}", "detail": "SOC internal error (HTTP 5xx)", "status_code": response.status_code, "buffered": True}
            else:
                # Other 4xx client errors (bad request / duplicate / forbidden) - do not infinite retry
                return False, {"error": f"HTTP {response.status_code}", "detail": response.text[:200], "status_code": response.status_code, "buffered": False}
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as e:
            # SOC unreachable - buffer event
            self._buffer_event(event_payload)
            return False, {"error": "ConnectionError", "detail": str(e), "buffered": True}
        except Exception as e:
            self._buffer_event(event_payload)
            return False, {"error": "UnexpectedError", "detail": str(e), "buffered": True}

    def _buffer_event(self, event_payload: Dict[str, Any]):
        """Persist event to local disk queue safely."""
        with self._lock:
            try:
                with open(self.spool_file, "a", encoding="utf-8") as f:
                    f.write(json.dumps(event_payload) + "\n")
            except Exception as err:
                print(f"[!] Warning: Failed to buffer event to spool: {err}")

    def flush_spool(self, max_batch: int = 50) -> int:
        """
        Attempt to replay queued events from disk.
        Returns count of successfully delivered events.
        """
        if not self.spool_file.exists():
            return 0

        with self._lock:
            try:
                with open(self.spool_file, "r", encoding="utf-8") as f:
                    lines = f.readlines()
            except Exception:
                return 0

            if not lines:
                return 0

            delivered_count = 0
            remaining_lines = []
            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
                "User-Agent": "HP-Victus-Security-Agent/1.0"
            }

            for idx, line in enumerate(lines):
                line_str = line.strip()
                if not line_str:
                    continue
                if delivered_count >= max_batch:
                    remaining_lines.extend(lines[idx:])
                    break

                try:
                    payload = json.loads(line_str)
                except Exception:
                    # Drop malformed line
                    continue

                try:
                    res = requests.post(self.endpoint, json=payload, headers=headers, timeout=5)
                    # 200, 201, 202 or 409 already ingested is considered consumed
                    if res.status_code in (200, 201, 202, 409):
                        delivered_count += 1
                    elif res.status_code >= 500:
                        # SOC still having server issues, stop batch and keep remaining
                        remaining_lines.extend(lines[idx:])
                        break
                    else:
                        # Permanent client error (4xx), drop line
                        pass
                except Exception:
                    # Connection failure, keep remaining
                    remaining_lines.extend(lines[idx:])
                    break

            # Rewrite remaining un-delivered events back to spool file
            try:
                with open(self.spool_file, "w", encoding="utf-8") as f:
                    f.writelines(remaining_lines)
            except OSError as err:
                print(f"[!] Spool file write warning: {err}")

            return delivered_count

    def _flush_spool_quietly(self):
        """Silently flush queued spool in background if spool exists."""
        if self.spool_file.exists() and self.spool_file.stat().st_size > 0:
            try:
                self.flush_spool(max_batch=10)
            except (OSError, requests.exceptions.RequestException):
                return

