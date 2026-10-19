import os
import json
import logging
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, Optional

class EventLogger:
    """Logs security events locally on HP Victus server and forwards to SOC."""

    def __init__(self, log_dir: Optional[str] = None):
        base_dir = Path(__file__).resolve().parent.parent
        self.log_dir = Path(log_dir) if log_dir else (base_dir / "logs")
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.log_file = self.log_dir / "security.log"

        # Setup local file logger
        self.logger = logging.getLogger("hp_victus_security")
        self.logger.setLevel(logging.INFO)
        if not self.logger.handlers:
            handler = logging.FileHandler(str(self.log_file))
            formatter = logging.Formatter('{"time":"%(asctime)s", "level":"%(levelname)s", "event":%(message)s}')
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)

    def log_and_format(
        self,
        event_id: str,
        event_type: str,
        severity: str,
        source_ip: str,
        destination_port: Optional[int] = None,
        source_port: Optional[int] = None,
        protocol: str = "TCP",
        message: str = "",
        metadata: Optional[Dict[str, Any]] = None,
        is_test: int = 0,
        signature: Optional[str] = None,
        alert_type: Optional[str] = None
    ) -> Dict[str, Any]:
        """Construct structured event and write to local security log."""
        try:
            from datetime import timezone
            ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")
        except Exception:
            ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%SZ")

        sig = signature or alert_type or event_type
        event = {
            "event_id": event_id,
            "timestamp": ts,
            "source": "hp-server",
            "event_type": event_type,
            "signature": sig,
            "alert_type": sig,
            "severity": severity,
            "source_ip": source_ip,
            "destination_ip": os.getenv("CN_SERVER_IP"),
            "source_port": source_port,
            "destination_port": destination_port,
            "protocol": protocol,
            "message": message,
            "metadata": metadata or {},
            "is_test": is_test
        }
        self.logger.info(json.dumps(event))
        return event
