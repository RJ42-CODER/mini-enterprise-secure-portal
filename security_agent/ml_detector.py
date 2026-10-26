"""
Machine-Learning Readiness Interface & Anomaly Feature Transformation Engine.

Prepares a normalized feature extraction and prediction interface for future
machine-learning anomaly detection and network intrusion models.
Preserves architectural separation between deterministic rules and probabilistic models.
Guarantees strict privacy redaction: credentials, tokens, and cookies are stripped
prior to feature extraction. Treats model predictions strictly as investigative signals.
"""

import os
import re
import math
from typing import Dict, Any, Optional, Tuple, List


# Sensitive parameter names to redact before feature transformation
SENSITIVE_PARAM_NAMES = {
    "password", "pass", "pwd", "secret", "token", "api_key", "apikey",
    "access_token", "auth", "authorization", "cookie", "session", "csrf"
}


class MLPrediction:
    """Standardized representation of machine-learning inference output."""

    __slots__ = (
        "model_name",
        "model_version",
        "predicted_class",
        "confidence_score",
        "feature_schema_version",
        "explanation",
        "is_investigative_signal"
    )

    def __init__(
        self,
        model_name: str,
        model_version: str,
        predicted_class: str,
        confidence_score: float,
        feature_schema_version: str = "1.0.0",
        explanation: Optional[Dict[str, Any]] = None
    ):
        self.model_name = model_name
        self.model_version = model_version
        self.predicted_class = predicted_class
        self.confidence_score = round(max(0.0, min(1.0, float(confidence_score))), 4)
        self.feature_schema_version = feature_schema_version
        self.explanation = explanation or {}
        # Model predictions are investigative signals, not definitive proof
        self.is_investigative_signal = True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "model_name": self.model_name,
            "model_version": self.model_version,
            "predicted_class": self.predicted_class,
            "confidence_score": self.confidence_score,
            "feature_schema_version": self.feature_schema_version,
            "is_investigative_signal": self.is_investigative_signal,
            "explanation": self.explanation
        }


class MLFeatureExtractor:
    """
    Transforms raw HTTP request context into sanitized, numerical/statistical features.
    Sanitizes and redacts all credentials, tokens, and sensitive personal parameters.
    """

    FEATURE_SCHEMA_VERSION = "1.0.0"

    @staticmethod
    def sanitize_body_and_query(query_string: str = "", body: str = "") -> Tuple[str, str]:
        """Strip and redact any sensitive parameter values from query string and body."""
        def _sanitize_kv_string(s: str) -> str:
            if not s:
                return ""
            pairs = s.split("&")
            sanitized = []
            for pair in pairs:
                if "=" in pair:
                    k, v = pair.split("=", 1)
                    k_clean = k.strip().lower()
                    if k_clean in SENSITIVE_PARAM_NAMES:
                        sanitized.append(f"{k}=[REDACTED]")
                    else:
                        sanitized.append(pair)
                else:
                    sanitized.append(pair)
            return "&".join(sanitized)

        return _sanitize_kv_string(query_string), _sanitize_kv_string(body)

    @classmethod
    def extract_features(
        cls,
        path: str,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        query_string: str = "",
        body: str = "",
        content_length: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Extract numerical and structural feature vector from sanitized HTTP request.
        """
        headers = headers or {}
        sanitized_query, sanitized_body = cls.sanitize_body_and_query(query_string, body)

        clean_path = path.split("?")[0] if path else "/"
        path_length = len(clean_path)
        path_depth = clean_path.count("/")

        query_length = len(sanitized_query)
        query_param_count = len(sanitized_query.split("&")) if sanitized_query else 0

        actual_body_length = content_length if content_length is not None else len(sanitized_body)

        # Character entropy and special character ratio across URI
        full_uri = f"{clean_path}?{sanitized_query}" if sanitized_query else clean_path
        total_chars = max(len(full_uri), 1)
        special_chars = len(re.findall(r"[^a-zA-Z0-9_\-\.\/]", full_uri))
        special_char_ratio = round(special_chars / total_chars, 4)

        digits = len(re.findall(r"\d", full_uri))
        digit_ratio = round(digits / total_chars, 4)

        # User-Agent token count
        ua = headers.get("User-Agent", "")
        ua_token_count = len(ua.split()) if ua else 0

        # Method encoding
        method_upper = method.upper()
        is_get = 1 if method_upper == "GET" else 0
        is_post = 1 if method_upper == "POST" else 0
        is_uncommon_method = 1 if method_upper not in ("GET", "POST", "HEAD") else 0

        # Shannon entropy calculation of URI characters
        char_counts: Dict[str, int] = {}
        for c in full_uri:
            char_counts[c] = char_counts.get(c, 0) + 1
        entropy = 0.0
        for count in char_counts.values():
            p = count / total_chars
            entropy -= p * math.log2(p)
        entropy = round(entropy, 4)

        return {
            "schema_version": cls.FEATURE_SCHEMA_VERSION,
            "path_length": path_length,
            "path_depth": path_depth,
            "query_length": query_length,
            "query_param_count": query_param_count,
            "body_length": actual_body_length,
            "header_count": len(headers),
            "special_char_ratio": special_char_ratio,
            "digit_ratio": digit_ratio,
            "uri_entropy": entropy,
            "ua_token_count": ua_token_count,
            "is_get": is_get,
            "is_post": is_post,
            "is_uncommon_method": is_uncommon_method
        }


class BaselineHeuristicModel:
    """
    Built-in lightweight baseline inference provider.
    Runs locally with zero external network dependencies and no heavy third-party packages.
    Identifies high-entropy or structural anomalies to demonstrate the ML prediction lifecycle.
    """

    MODEL_NAME = "baseline_statistical_anomaly_v1"
    MODEL_VERSION = "1.0.0"

    def predict(self, features: Dict[str, Any]) -> MLPrediction:
        """
        Evaluate extracted features.
        Returns MLPrediction with classification and confidence.
        """
        score = 0.0
        signals = []

        # High URI character entropy (indicative of encoding / obfuscation / random fuzzing)
        entropy = features.get("uri_entropy", 0.0)
        if entropy > 4.5:
            score += 0.35
            signals.append(f"Elevated URI character entropy ({entropy} > 4.5)")
        elif entropy > 3.8:
            score += 0.15

        # Abnormally high special character density
        special_ratio = features.get("special_char_ratio", 0.0)
        if special_ratio > 0.30:
            score += 0.35
            signals.append(f"High special character ratio ({special_ratio} > 0.30)")
        elif special_ratio > 0.15:
            score += 0.15

        # Path depth anomaly
        depth = features.get("path_depth", 0)
        if depth > 7:
            score += 0.20
            signals.append(f"Deep path traversal/nesting depth ({depth})")

        # Disallowed/uncommon HTTP method
        if features.get("is_uncommon_method", 0) == 1:
            score += 0.25
            signals.append("Uncommon HTTP method observed")

        confidence = round(min(score, 1.0), 4)

        if confidence >= 0.70:
            predicted_class = "suspicious_anomaly"
        elif confidence >= 0.40:
            predicted_class = "unknown"
        else:
            predicted_class = "normal"

        explanation = {
            "confidence_factors": signals,
            "anomaly_score": confidence,
            "classification_reason": (
                "Statistical feature threshold exceeded" if signals else "Within normal baseline distribution"
            )
        }

        return MLPrediction(
            model_name=self.MODEL_NAME,
            model_version=self.MODEL_VERSION,
            predicted_class=predicted_class,
            confidence_score=confidence,
            feature_schema_version=features.get("schema_version", "1.0.0"),
            explanation=explanation
        )


class MLAnomalyDetector:
    """
    Coordinates feature extraction and machine-learning anomaly inference.
    Treats predictions strictly as investigative signals; never blocks requests directly.
    """

    def __init__(self, model_provider: Optional[Any] = None, min_confidence: float = 0.65):
        self.enabled: bool = os.getenv("ML_DETECTOR_ENABLED", "true").lower() in ("1", "true", "yes")
        self.model = model_provider or BaselineHeuristicModel()
        self.min_confidence = min_confidence

    def evaluate_request(
        self,
        path: str,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        query_string: str = "",
        body: str = "",
        content_length: Optional[int] = None
    ) -> Optional[Dict[str, Any]]:
        """
        Extract features, run model prediction, and return structured investigative signal
        if an anomaly is flagged. Returns None if benign or disabled.
        """
        if not self.enabled:
            return None

        features = MLFeatureExtractor.extract_features(
            path=path,
            method=method,
            headers=headers,
            query_string=query_string,
            body=body,
            content_length=content_length
        )

        prediction: MLPrediction = self.model.predict(features)

        # Only surface predictions that indicate an anomaly or unknown with sufficient confidence
        if prediction.predicted_class in ("suspicious_anomaly", "unknown") and prediction.confidence_score >= self.min_confidence:
            return {
                "detected": True,
                "event_type": "ML_ANOMALY",
                "signature": "ML_HTTP_ANOMALY",
                "severity": "LOW" if prediction.predicted_class == "unknown" else "MEDIUM",
                "message": (
                    f"Machine-learning anomaly model ({prediction.model_name} v{prediction.model_version}) "
                    f"classified request as '{prediction.predicted_class}' with confidence {prediction.confidence_score}"
                ),
                "metadata": {
                    "model_prediction": prediction.to_dict(),
                    "features_summary": {k: v for k, v in features.items() if k != "schema_version"},
                    "investigative_signal_only": True,
                    "action_taken": "MONITORED",
                    "outcome": "INVESTIGATION_SIGNAL"
                }
            }

        return None
