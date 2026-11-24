"""Explainable AI (XAI) feature attribution for ThreatGuard.

Computes mathematically grounded feature attributions for Isolation Forest
and multi-detector anomalies using decision-tree split traversal and standardized deviations.
"""
from typing import Any, Dict, List, Optional, Tuple
import numpy as np

from backend.ml_engine.pipeline import FEATURES

# Human-readable descriptions for the 12 behavioral features
FEATURE_LABELS: Dict[str, str] = {
    "call_count": "API Call Burst",
    "call_velocity": "Call Velocity Spike",
    "error_ratio": "High Error Ratio",
    "unique_services": "Service Diversity",
    "unique_events": "Event Diversity",
    "enumeration_ratio": "Enumeration / Reconnaissance Ratio",
    "sensitive_count": "Sensitive / Critical Actions",
    "iam_change_count": "IAM Privilege Modifications",
    "first_service_ratio": "Unseen AWS Services",
    "first_ip": "New / First-Time Source IP",
    "off_hours": "Off-Hours Activity",
    "event_entropy": "Unusual Event Randomness",
}


def explain_isolation_forest_sample(
    model: Any,
    scaler: Any,
    x_raw: np.ndarray,
    x_transformed: np.ndarray,
    feature_names: List[str] = FEATURES,
    top_k: int = 5,
) -> List[Tuple[str, float]]:
    """Compute tree-path feature attribution across all decision trees in an Isolation Forest.

    Traces sample x through every tree in the ensemble, attributing isolation speed
    (drop in node sample density) to the specific feature split that isolated the point.

    Returns:
        List of (feature_description_with_value, percentage_weight) sorted descending.
    """
    n_features = len(feature_names)
    attributions = np.zeros(n_features, dtype=float)

    # Transform input vector if 1D
    x_row = x_transformed.reshape(1, -1) if x_transformed.ndim == 1 else x_transformed
    raw_row = x_raw.flatten() if x_raw.ndim == 1 else x_raw[0]

    # Iterate through all extra-trees in the isolation forest
    estimators = getattr(model, "estimators_", [])
    if not estimators:
        # Fallback to standardized z-score deviation if model has no estimators
        return explain_zscore_sample(scaler, x_raw, feature_names, top_k)

    for tree_estimator in estimators:
        tree = tree_estimator.tree_
        node = 0
        while tree.children_left[node] != tree.children_right[node]:  # Not a leaf
            feat_idx = tree.feature[node]
            thresh = tree.threshold[node]
            n_parent = float(tree.n_node_samples[node])

            if x_row[0, feat_idx] <= thresh:
                next_node = tree.children_left[node]
            else:
                next_node = tree.children_right[node]

            n_child = float(tree.n_node_samples[next_node])
            # Information isolation gain: how rapidly this split isolates the sample
            gain = max(0.0, np.log2(n_parent) - np.log2(n_child + 1.0))
            attributions[feat_idx] += gain
            node = next_node

    # If all attributions zero, combine with standardized z-score
    if attributions.sum() <= 1e-9:
        return explain_zscore_sample(scaler, x_raw, feature_names, top_k)

    # Normalize attributions to percentage shares summing to 1.0
    shares = attributions / attributions.sum()
    sorted_indices = np.argsort(-shares)

    results = []
    for idx in sorted_indices[:top_k]:
        feat = feature_names[idx]
        label = FEATURE_LABELS.get(feat, feat)
        val = raw_row[idx]
        val_str = f"{val:.2f}" if isinstance(val, float) and not val.is_integer() else f"{int(val)}"
        if feat == "error_ratio":
            val_str = f"{round(val * 100)}%"
        elif feat == "enumeration_ratio":
            val_str = f"{round(val * 100)}%"
        elif feat == "first_ip":
            val_str = "Yes (New IP)" if val > 0.5 else "Known IP"
        elif feat == "off_hours":
            val_str = "Yes (Odd Hour)" if val > 0.5 else "Normal Business Hours"

        results.append([f"{label}: {val_str}", round(float(shares[idx]), 3)])

    return results


def explain_zscore_sample(
    scaler: Any,
    x_raw: np.ndarray,
    feature_names: List[str] = FEATURES,
    top_k: int = 5,
) -> List[Tuple[str, float]]:
    """Compute feature attribution using standardized deviation from benign baseline."""
    raw_row = x_raw.flatten() if x_raw.ndim == 1 else x_raw[0]
    mean = getattr(scaler, "mean_", np.zeros(len(feature_names)))
    var = getattr(scaler, "var_", np.ones(len(feature_names)))
    std = np.maximum(np.sqrt(var), 0.1)

    z = np.abs((raw_row - mean) / std)
    z_sum = z.sum() if z.sum() > 0 else 1.0
    shares = z / z_sum
    sorted_indices = np.argsort(-shares)

    results = []
    for idx in sorted_indices[:top_k]:
        feat = feature_names[idx]
        label = FEATURE_LABELS.get(feat, feat)
        val = raw_row[idx]
        val_str = f"{val:.2f}" if isinstance(val, float) and not val.is_integer() else f"{int(val)}"
        results.append([f"{label}: {val_str}", round(float(shares[idx]), 3)])

    return results
