"""
Extensible Detection Pipeline & Normalized Security Interface.

Provides a unified, extensible architecture orchestrating:
  1. Deterministic Rule-Based Inspection (WAF: SQLi, CMDi, Path Traversal, Brute-Force Auth, Dir Fuzz)
  2. HTTP Rate-Anomaly Detection (Sliding-window velocity and burst tracking)
  3. Machine-Learning Anomaly Detection (Investigative feature-based signals)

Normalizes event schema, severity levels, telemetry identifiers, and mitigation evidence
across all detection tiers while keeping detection strictly separated from automated enforcement.
"""

import abc
import time
from typing import Dict, Any, Optional, List, Tuple
from dataclasses import dataclass, field


@dataclass
class RequestContext:
    """Standardized representation of an inbound HTTP request for the detection pipeline."""
    source_ip: str
    path: str
    method: str = "GET"
    headers: Dict[str, str] = field(default_factory=dict)
    query_string: str = ""
    body: str = ""
    content_length: Optional[int] = None
    remote_addr: Optional[str] = None
    timestamp: float = field(default_factory=time.time)


@dataclass
class DetectionResult:
    """Normalized output produced by any pipeline detection module."""
    detected: bool
    module_name: str
    category: str  # "RULE_BASED", "RATE_ANOMALY", "MACHINE_LEARNING"
    event_type: str
    signature: str
    severity: str  # "LOW", "MEDIUM", "HIGH", "CRITICAL"
    message: str
    metadata: Dict[str, Any] = field(default_factory=dict)
    blocked: bool = False
    status_code: int = 200
    action_taken: str = "MONITORED"
    outcome: str = "REPORTED"
    client_message: Optional[str] = None
    verification_evidence: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "detected": self.detected,
            "module_name": self.module_name,
            "category": self.category,
            "event_type": self.event_type,
            "signature": self.signature,
            "severity": self.severity,
            "message": self.message,
            "metadata": self.metadata,
            "blocked": self.blocked,
            "status_code": self.status_code,
            "action_taken": self.action_taken,
            "outcome": self.outcome,
            "client_message": self.client_message,
            "verification_evidence": self.verification_evidence
        }


class BaseDetectionModule(abc.ABC):
    """Abstract base class for all detection pipeline modules."""

    @property
    @abc.abstractmethod
    def name(self) -> str:
        """Unique identifier of the detection module."""
        pass

    @property
    @abc.abstractmethod
    def category(self) -> str:
        """Module category: 'RULE_BASED', 'RATE_ANOMALY', or 'MACHINE_LEARNING'."""
        pass

    @abc.abstractmethod
    def evaluate(self, ctx: RequestContext) -> Optional[DetectionResult]:
        """Evaluate request context and return DetectionResult if triggered, or None if benign."""
        pass


class ExtensibleDetectionPipeline:
    """
    Coordinates ordered evaluation of security detection modules.
    Ensures deterministic perimeter rules are evaluated first, followed by rate anomalies
    and investigative machine-learning inference.
    """

    def __init__(self):
        self._modules: List[BaseDetectionModule] = []

    def register_module(self, module: BaseDetectionModule):
        """Add a detection module to the pipeline."""
        self._modules.append(module)

    def get_modules(self) -> List[BaseDetectionModule]:
        """Return list of registered modules."""
        return list(self._modules)

    def evaluate_all(self, ctx: RequestContext) -> List[DetectionResult]:
        """
        Run request context through all registered modules in order.
        Returns all positive detection results.
        If a blocking deterministic rule triggers, pipeline stops early to protect backend.
        """
        results: List[DetectionResult] = []
        for module in self._modules:
            try:
                res = module.evaluate(ctx)
                if res and res.detected:
                    results.append(res)
                    # If a deterministic blocking rule triggered, do not continue down pipeline
                    if res.blocked:
                        break
            except Exception as err:
                print(f"[!] Warning: Exception during {module.name} evaluation: {err}")
        return results
