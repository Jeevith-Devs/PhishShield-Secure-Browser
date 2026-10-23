"""
PhishShield ML Inference Wrapper
Loads trained model weights and serves fast predictions for the FastAPI backend.
Falls back to heuristic scoring if models are not yet trained.
"""
import os
import sys
from pathlib import Path
from typing import Dict, Any, Optional, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

MODELS_DIR = Path(__file__).parent / "weights"

_xgb_model = None
_rf_model = None
_lr_model = None
_scaler = None
_models_loaded = False


def _try_load_models():
    """Lazy-loads trained model weights if available."""
    global _xgb_model, _rf_model, _lr_model, _scaler, _models_loaded
    if _models_loaded:
        return
    try:
        import joblib
        scaler_path = MODELS_DIR / "scaler.joblib"
        if scaler_path.exists():
            _scaler = joblib.load(scaler_path)
        xgb_path = MODELS_DIR / "xgboost.joblib"
        if xgb_path.exists():
            _xgb_model = joblib.load(xgb_path)
        rf_path = MODELS_DIR / "random_forest.joblib"
        if rf_path.exists():
            _rf_model = joblib.load(rf_path)
        lr_path = MODELS_DIR / "logistic_regression.joblib"
        if lr_path.exists():
            _lr_model = joblib.load(lr_path)
        _models_loaded = True
    except Exception as e:
        print(f"[PhishShield ML] Model loading failed: {e} — using heuristic fallback.")
        _models_loaded = True


FEATURE_COLUMNS = [
    "url_length", "hostname_length", "path_length", "query_length",
    "dot_count", "hyphen_count", "underscore_count", "slash_count",
    "question_count", "equal_count", "at_count", "ampersand_count",
    "percent_count", "digit_count", "letter_count", "digit_ratio",
    "letter_ratio", "is_ip_address", "subdomain_count", "hostname_entropy",
    "has_punycode", "is_high_risk_tld", "is_https", "has_double_slash_in_path",
    "has_port_in_url", "keyword_count", "has_suspicious_keyword", "brand_count",
    "has_brand_in_subdomain", "url_entropy", "path_entropy",
    "dot_in_hostname", "hyphen_in_hostname", "digit_in_hostname",
    "param_count", "has_www", "consecutive_dots", "consecutive_hyphens",
]


def predict(features: Dict[str, Any]) -> Tuple[float, str]:
    """
    Returns (phishing_probability: float 0-1, model_used: str).
    Uses the best available model: XGBoost > Random Forest > Logistic Regression > Heuristic.
    """
    _try_load_models()

    try:
        import numpy as np
        feature_vector = [[features.get(col, 0) for col in FEATURE_COLUMNS]]
        arr = np.array(feature_vector)

        if _xgb_model is not None:
            prob = float(_xgb_model.predict_proba(arr)[0][1])
            return prob, "XGBoost (Calibrated)"

        if _rf_model is not None:
            prob = float(_rf_model.predict_proba(arr)[0][1])
            return prob, "RandomForest (Calibrated)"

        if _lr_model is not None and _scaler is not None:
            arr_scaled = _scaler.transform(arr)
            prob = float(_lr_model.predict_proba(arr_scaled)[0][1])
            return prob, "LogisticRegression (Calibrated)"

    except Exception as e:
        print(f"[PhishShield ML] Inference error: {e}")

    # Heuristic fallback
    risk = 0.0
    if features.get("is_ip_address"):        risk += 0.35
    if features.get("has_brand_in_subdomain"): risk += 0.40
    if features.get("is_high_risk_tld"):     risk += 0.25
    if features.get("has_suspicious_keyword"): risk += 0.15 * min(3, features.get("keyword_count", 0))
    if features.get("has_punycode"):         risk += 0.30
    if features.get("subdomain_count", 0) > 3: risk += 0.20
    if features.get("url_length", 0) > 100: risk += 0.10
    if features.get("at_count", 0) > 0:     risk += 0.25
    return min(0.99, max(0.02, risk)), "Heuristic (model not trained)"


def is_model_available() -> bool:
    """Returns True if at least one trained model is loaded."""
    _try_load_models()
    return any(m is not None for m in [_xgb_model, _rf_model, _lr_model])
