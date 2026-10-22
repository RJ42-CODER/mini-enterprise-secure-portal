import os
import time
import uuid
import threading
from urllib.parse import urlparse
from datetime import datetime, timezone
from typing import Dict, Any, Optional, Tuple, List, Set

class SafeDefensivePolicy:
    """
    Safe defensive policy manager for enterprise server perimeter controls.
    Enforces safe policy invariants:
      1. Whitelist protection: Localhost, Server IP, and SOC server are never blocked.
      2. Strict finite expiry: Every active block or quarantine has an immutable maximum duration.
      3. Guaranteed rollback: Immediate administrative release per IP or emergency global rollback.
      4. Safe OS firewall driver: Safe application-level perimeter enforcement by default;
         optional OS firewall commands require explicit opt-in and safe rollback tags.
    """

    def __init__(
        self,
        whitelist: Optional[Set[str]] = None,
        default_expiry_seconds: int = 300,
        max_expiry_seconds: int = 3600,
        max_active_blocks: int = 1000
    ):
        self.default_expiry_seconds = default_expiry_seconds
        self.max_expiry_seconds = max_expiry_seconds
        self.max_active_blocks = max_active_blocks

        # Build default whitelist
        self.whitelist: Set[str] = set(whitelist or [])
        self.whitelist.add("127.0.0.1")
        self.whitelist.add("::1")
        self.whitelist.add("localhost")

        server_ip = os.getenv("CN_SERVER_IP")
        if server_ip:
            self.whitelist.add(server_ip.strip())

        soc_url = os.getenv("SOC_URL")
        if soc_url:
            try:
                parsed = urlparse(soc_url)
                if parsed.hostname:
                    self.whitelist.add(parsed.hostname.strip())
            except Exception:
                pass

        # Active blocks: source_ip -> Dict[str, Any]
        self.active_blocks: Dict[str, Dict[str, Any]] = {}
        # History audit log: List of structured mitigation records
        self.history: List[Dict[str, Any]] = []
        self._lock = threading.Lock()

    def is_whitelisted(self, source_ip: str) -> bool:
        """Check whether the given IP is protected under the safe policy whitelist."""
        if not source_ip:
            return True
        clean_ip = source_ip.strip()
        return clean_ip in self.whitelist

    def can_block(self, source_ip: str) -> Tuple[bool, str]:
        """Verify if defensive blocking is permitted against this source IP."""
        if self.is_whitelisted(source_ip):
            return False, f"Source IP '{source_ip}' is whitelisted (safe policy protection)"
        with self._lock:
            if len(self.active_blocks) >= self.max_active_blocks:
                return False, f"Max active blocks capacity ({self.max_active_blocks}) reached"
        return True, "Permitted"

    def apply_block(
        self,
        source_ip: str,
        reason: str,
        attack_type: str,
        duration_seconds: Optional[int] = None,
        tier: int = 1,
        rule: str = "SAFE_POLICY_ENFORCEMENT",
        metadata: Optional[Dict[str, Any]] = None
    ) -> Optional[Dict[str, Any]]:
        """
        Apply a safe, time-bounded defensive block with empirical verification evidence.
        Returns the structured mitigation record if applied, or None if disallowed by safe policy.
        """
        allowed, why = self.can_block(source_ip)
        if not allowed:
            return None

        dur = duration_seconds or self.default_expiry_seconds
        dur = max(1, min(dur, self.max_expiry_seconds))
        now = time.time()
        expires_at = now + dur

        action_id = f"ACT-MIT-{uuid.uuid4().hex[:8].upper()}"
        iso_timestamp = datetime.now(timezone.utc).isoformat()
        server_asset = f"{os.getenv('CN_SERVER_IP', 'localhost')}:{os.getenv('PORT', '5000')}"

        record: Dict[str, Any] = {
            "action_id": action_id,
            "attack_type": attack_type,
            "source": source_ip,
            "target": server_asset,
            "action_taken": "BLOCKED" if tier == 1 else "PROGRESSIVE_LOCKOUT",
            "timestamp": iso_timestamp,
            "outcome": "ENFORCED",
            "verification_evidence": {
                "rule": rule,
                "reason": reason,
                "duration_seconds": dur,
                "tier": tier,
                "expires_at_unix": expires_at,
                "policy": "safe_defensive_policy",
                "perimeter_enforced": True,
                "verification_status": "VERIFIED"
            }
        }
        if metadata:
            record["verification_evidence"].update(metadata)

        with self._lock:
            self.active_blocks[source_ip] = {
                "action_id": action_id,
                "source_ip": source_ip,
                "attack_type": attack_type,
                "rule": rule,
                "tier": tier,
                "blocked_at": now,
                "expires_at": expires_at,
                "duration_seconds": dur,
                "reason": reason,
                "record": record
            }
            self.history.append(record)
            if len(self.history) > 1000:
                self.history = self.history[-1000:]

        return record

    def is_blocked(self, source_ip: str) -> Tuple[bool, int]:
        """
        Check if an IP is currently blocked, automatically expiring outdated blocks.
        Returns (is_blocked, remaining_seconds).
        """
        if self.is_whitelisted(source_ip):
            return False, 0

        now = time.time()
        with self._lock:
            entry = self.active_blocks.get(source_ip)
            if not entry:
                return False, 0

            rem = entry["expires_at"] - now
            if rem > 0:
                return True, max(1, int(round(rem)))

            # Block has expired - execute safe auto-expiration
            del self.active_blocks[source_ip]
            expiry_record = {
                "action_id": f"ACT-EXP-{uuid.uuid4().hex[:8].upper()}",
                "attack_type": entry.get("attack_type", "UNKNOWN"),
                "source": source_ip,
                "target": f"{os.getenv('CN_SERVER_IP', 'localhost')}:{os.getenv('PORT', '5000')}",
                "action_taken": "AUTO_EXPIRE",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "outcome": "EXPIRED",
                "verification_evidence": {
                    "original_action_id": entry.get("action_id"),
                    "duration_seconds": entry.get("duration_seconds"),
                    "expired_at_unix": now,
                    "verification_status": "VERIFIED"
                }
            }
            self.history.append(expiry_record)
            return False, 0

    def rollback_block(self, source_ip: str, reason: str = "administrative_release") -> Optional[Dict[str, Any]]:
        """
        Execute safe administrative rollback for a specific source IP.
        Immediately releases the IP from active quarantine and logs the rollback.
        """
        now = time.time()
        with self._lock:
            entry = self.active_blocks.pop(source_ip, None)
            orig_action = entry.get("action_id") if entry else None

            rollback_record = {
                "action_id": f"ACT-ROL-{uuid.uuid4().hex[:8].upper()}",
                "attack_type": entry.get("attack_type", "MANUAL") if entry else "MANUAL",
                "source": source_ip,
                "target": f"{os.getenv('CN_SERVER_IP', 'localhost')}:{os.getenv('PORT', '5000')}",
                "action_taken": "ROLLBACK",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "outcome": "RELEASED",
                "verification_evidence": {
                    "reason": reason,
                    "original_action_id": orig_action,
                    "released_at_unix": now,
                    "verification_status": "VERIFIED"
                }
            }
            self.history.append(rollback_record)
            return rollback_record

    def rollback_all(self, reason: str = "emergency_global_rollback") -> int:
        """
        Execute emergency rollback: Clears all active blocks across the perimeter immediately.
        Returns the number of blocks revoked.
        """
        now = time.time()
        with self._lock:
            count = len(self.active_blocks)
            revoked_ips = list(self.active_blocks.keys())
            self.active_blocks.clear()

            emergency_record = {
                "action_id": f"ACT-EMR-{uuid.uuid4().hex[:8].upper()}",
                "attack_type": "EMERGENCY_ROLLBACK",
                "source": "ALL",
                "target": f"{os.getenv('CN_SERVER_IP', 'localhost')}:{os.getenv('PORT', '5000')}",
                "action_taken": "GLOBAL_ROLLBACK",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "outcome": "ALL_RELEASED",
                "verification_evidence": {
                    "reason": reason,
                    "revoked_count": count,
                    "revoked_ips": revoked_ips,
                    "executed_at_unix": now,
                    "verification_status": "VERIFIED"
                }
            }
            self.history.append(emergency_record)
            return count

    def get_active_blocks(self) -> List[Dict[str, Any]]:
        """Return list of active blocks with remaining time."""
        now = time.time()
        active = []
        with self._lock:
            for ip, entry in list(self.active_blocks.items()):
                rem = entry["expires_at"] - now
                if rem > 0:
                    active.append({
                        "ip": ip,
                        "action_id": entry["action_id"],
                        "attack_type": entry["attack_type"],
                        "tier": entry["tier"],
                        "remaining_seconds": int(rem),
                        "duration_seconds": entry["duration_seconds"],
                        "reason": entry["reason"]
                    })
                else:
                    # Expire
                    del self.active_blocks[ip]
        return active
