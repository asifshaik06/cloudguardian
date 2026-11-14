"""Runtime multi-detector ML inference engine for CloudGuardian.

Loads models/baseline_v1.joblib:
- StandardScaler
- IsolationForest (200 estimators)
- LocalOutlierFactor
- OneClassSVM
- 99th percentile validation decision thresholds

Performs live inference over 12-feature streaming windows with XAI attribution.
"""
import logging
import os
from typing import Any, Dict, List, Optional
import joblib
import numpy as np

from backend.ml_engine.pipeline import FEATURES
from backend.ml_engine.xai import explain_isolation_forest_sample

logger = logging.getLogger("cloudguardian.detector")

LOG_FEATURES = ["call_count", "call_velocity", "unique_services", "unique_events", "sensitive_count", "iam_change_count"]


class RuntimeDetector:
    """Multi-detector anomaly inference engine backed by baseline_v1.joblib."""

    def __init__(self, model_path: str = "models/baseline_v1.joblib"):
        self.model_path = model_path
        self.scaler: Any = None
        self.models: Dict[str, Any] = {}
        self.thresholds: Dict[str, float] = {}
        self.features: List[str] = FEATURES
        self.log_features: List[str] = LOG_FEATURES
        self._load_model()

    def _load_model(self) -> None:
        """Load trained baseline artifacts or initialize fallback."""
        if os.path.exists(self.model_path):
            try:
                card = joblib.load(self.model_path)
                self.scaler = card.get("scaler")
                self.models = card.get("models", {})
                self.thresholds = card.get("thresholds", {})
                self.features = card.get("features", FEATURES)
                self.log_features = card.get("log_features", LOG_FEATURES)
                logger.info("Loaded runtime detector from %s with %d models", self.model_path, len(self.models))
                return
            except Exception as exc:
                logger.warning("Error loading %s: %s. Using fallback initialization.", self.model_path, exc)

        # Fallback initialization for test isolation
        from sklearn.ensemble import IsolationForest
        from sklearn.preprocessing import StandardScaler
        rng = np.random.default_rng(0)
        X_dummy = rng.uniform(0.1, 5.0, (100, len(self.features)))
        self.scaler = StandardScaler().fit(X_dummy)
        self.models = {
            "isolation_forest": IsolationForest(n_estimators=50, random_state=0).fit(X_dummy),
        }
        self.thresholds = {
            "isolation_forest": 0.5,
            "zscore": 3.0,
        }

    def score_window(self, features_dict: Dict[str, float]) -> Dict[str, Any]:
        """Score a 12-feature window dictionary against all detectors.

        Returns:
            Dict containing:
                - is_anomaly: bool (Isolation Forest score > threshold)
                - score: float (Isolation Forest anomaly score)
                - threshold: float
                - scores: Dict[detector_name, score]
                - explanations: List[Tuple[str, float]]
                - features: Dict[str, float]
        """
        # 1. Assemble raw feature vector in exact feature order
        x_raw = np.array([[features_dict.get(f, 0.0) for f in self.features]], dtype=float)

        # 2. Apply log1p transform to designated count features
        x_log = x_raw.copy()
        for idx, f in enumerate(self.features):
            if f in self.log_features:
                x_log[0, idx] = np.log1p(max(0.0, x_log[0, idx]))

        # 3. Standardize using training scaler
        x_scaled = self.scaler.transform(x_log)

        # 4. Compute detector scores
        iso_model = self.models.get("isolation_forest")
        score_if = float(-iso_model.score_samples(x_scaled)[0]) if iso_model else 0.0

        # Z-score detector with variance floor
        var_floor = np.maximum(np.sqrt(self.scaler.var_), 0.1)
        z_scores = np.abs((x_log[0] - self.scaler.mean_) / var_floor)
        score_z = float(z_scores.max())

        ocsvm_model = self.models.get("ocsvm")
        score_ocsvm = float(-ocsvm_model.score_samples(x_scaled)[0]) if ocsvm_model else 0.0

        lof_model = self.models.get("lof")
        score_lof = float(-lof_model.score_samples(x_scaled)[0]) if lof_model else 0.0

        threshold_if = self.thresholds.get("isolation_forest", 0.610)
        is_anomaly = score_if > threshold_if

        # 5. Compute TreeSHAP / tree feature explanations
        explanations: List[List[Any]] = []
        if is_anomaly or score_z > self.thresholds.get("zscore", 4.4):
            explanations = explain_isolation_forest_sample(
                iso_model,
                self.scaler,
                x_raw,
                x_scaled,
                self.features,
                top_k=5,
            )

        return {
            "is_anomaly": is_anomaly,
            "score": round(score_if, 4),
            "threshold": round(threshold_if, 4),
            "scores": {
                "isolation_forest": round(score_if, 4),
                "zscore": round(score_z, 4),
                "ocsvm": round(score_ocsvm, 4),
                "lof": round(score_lof, 4),
            },
            "explanations": explanations,
            "features": features_dict,
        }
