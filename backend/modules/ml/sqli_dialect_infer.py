#!/usr/bin/env python3
"""
SQLi Dialect Classifier Inference

Loads the SQLi dialect text model + vectorizer and provides prediction.
Mirrors the XSS context loader for consistency and robustness.
"""

from typing import Dict, Any, Optional, Tuple
from threading import Lock
from pathlib import Path
import joblib
import numpy as np

from backend.app_state import MODEL_DIR

# Globals with thread-safe lazy load
_dialect_model = None
_dialect_vectorizer = None
_alt_model = None  # fallback: may be a Pipeline or a compact classifier
_tau_unknown = 0.6
_load_lock = Lock()

# Map label variants to canonical names used across the codebase
_LABEL_CANON = {
    "postgres": "postgresql",
    "postgresql": "postgresql",
    "mysql": "mysql",
    "mssql": "mssql",
    "sqlite": "sqlite",
    "oracle": "oracle",
    "unknown": "unknown",
}

def load_models() -> bool:
    """Load model and vectorizer from MODEL_DIR if available."""
    global _dialect_model, _dialect_vectorizer

    if _dialect_model is not None and _dialect_vectorizer is not None:
        return True

    with _load_lock:
        if _dialect_model is not None and _dialect_vectorizer is not None:
            return True

        try:
            model_path = MODEL_DIR / "sqli_dialect_model.joblib"
            vectorizer_path = MODEL_DIR / "sqli_dialect_vectorizer.joblib"
            alt_model_path = MODEL_DIR / "sqli_dialect_classifier.joblib"

            loaded_any = False

            if model_path.exists():
                _dialect_model = joblib.load(model_path, mmap_mode=None)
                print(f"SQLi dialect model loaded from {model_path}")
                loaded_any = True
            if vectorizer_path.exists():
                _dialect_vectorizer = joblib.load(vectorizer_path, mmap_mode=None)
                loaded_any = True or loaded_any
            if alt_model_path.exists():
                # This may be a sklearn Pipeline or a compact classifier
                try:
                    global _alt_model
                    _alt_model = joblib.load(alt_model_path, mmap_mode=None)
                    print(f"SQLi dialect alt-model loaded from {alt_model_path}")
                    loaded_any = True or loaded_any
                except Exception as e:
                    print(f"Failed to load SQLi alt-model: {e}")

            # Load pipeline meta (for tau_unknown) if present
            try:
                import json
                meta_path = MODEL_DIR / 'sqli_dialect_pipeline_meta.json'
                if meta_path.exists():
                    data = json.loads(meta_path.read_text())
                    tau = data.get('tau_unknown')
                    if isinstance(tau, (int, float)):
                        global _tau_unknown
                        _tau_unknown = float(tau)
            except Exception:
                pass

            if not loaded_any:
                print(f"SQLi dialect assets missing: model={model_path.exists()} vectorizer={vectorizer_path.exists()} alt_model={alt_model_path.exists()}")
                return False
            return True
        except Exception as e:
            print(f"Failed to load SQLi dialect model/vectorizer: {e}")
            return False

def _build_text_features(response_text: str, headers: dict, status_code: int = None) -> str:
    """Build the text feature string similar to training."""
    text = response_text or ""

    # Minimal augmentation: include coarse context hints
    ct = (headers or {}).get("content-type", "").lower()
    if "text/html" in ct:
        text += " CT_HTML"
    if "application/json" in ct:
        text += " CT_JSON"
    if status_code is not None:
        text += f" HTTP_{int(status_code)}"

    return text

def _predict_with_model(text: str) -> Optional[Tuple[str, float, Dict[str, float]]]:
    """Try various backends to obtain a prediction from loaded assets."""
    # 1) If we have a vectorizer and a plain classifier, ensure feature dims match
    if _dialect_model is not None and _dialect_vectorizer is not None:
        try:
            X = _dialect_vectorizer.transform([text])
            # Some sklearn versions expose n_features_in_
            n_expected = getattr(_dialect_model, 'n_features_in_', None)
            if n_expected is not None and X.shape[1] != n_expected:
                raise ValueError(f"vectorizer/features mismatch: X={X.shape[1]} expected={n_expected}")
            proba_row = _dialect_model.predict_proba(X)[0]
            classes = getattr(_dialect_model, 'classes_', None)
            if classes is None:
                return None
            best_idx = int(np.argmax(proba_row))
            raw_label = str(classes[best_idx])
            label = _LABEL_CANON.get(raw_label, raw_label)
            all_probas: Dict[str, float] = {}
            for cls, p in zip(classes, proba_row):
                all_probas[_LABEL_CANON.get(str(cls), str(cls))] = float(p)
            return label, float(proba_row[best_idx]), all_probas
        except Exception as e:
            print(f"Primary model/vectorizer prediction failed: {e}")

    # 2) If alt-model is a Pipeline, it may accept raw text directly
    if _alt_model is not None:
        try:
            proba_row = _alt_model.predict_proba([text])[0]
            classes = getattr(_alt_model, 'classes_', None)
            if classes is None:
                return None
            best_idx = int(np.argmax(proba_row))
            max_p = float(proba_row[best_idx])
            raw_label = str(classes[best_idx])
            label = _LABEL_CANON.get(raw_label, raw_label)
            if max_p < _tau_unknown:
                label = 'unknown'
            all_probas: Dict[str, float] = {}
            for cls, p in zip(classes, proba_row):
                all_probas[_LABEL_CANON.get(str(cls), str(cls))] = float(p)
            return label, max_p, all_probas
        except Exception as e:
            print(f"Alt-model direct text prediction failed: {e}")

    # 3) Try numeric feature fallback for compact classifiers
    try:
        if _alt_model is not None:
            # Build numeric features similar to earlier simple classifier
            # [error_text_length, status_code, content_type_html, content_type_json]
            # Here we can't access headers/status; handled in outer function.
            return None  # Defer to outer, which knows headers/status
    except Exception:
        pass
    return None


def predict_sqli_dialect(response_text: str, headers: dict, status_code: int = None) -> Optional[Dict[str, Any]]:
    """Predict SQLi dialect using the trained text model + vectorizer."""
    if not load_models():
        return None

    try:
        text = _build_text_features(response_text, headers, status_code)
        out = _predict_with_model(text)
        if out is None:
            # Numeric fallback only if we have an alt model and dimensionality suggests it
            if _alt_model is not None:
                try:
                    ct = (headers or {}).get("content-type", "").lower()
                    features = np.array([
                        len(response_text or ""),
                        int(status_code or 0),
                        1 if "text/html" in ct else 0,
                        1 if "application/json" in ct else 0,
                    ]).reshape(1, -1)
                    proba_row = _alt_model.predict_proba(features)[0]
                    classes = getattr(_alt_model, 'classes_', None)
                    if classes is not None:
                        best_idx = int(np.argmax(proba_row))
                        raw_label = str(classes[best_idx])
                        label = _LABEL_CANON.get(raw_label, raw_label)
                        all_probas = { _LABEL_CANON.get(str(c), str(c)): float(p) for c, p in zip(classes, proba_row)}
                        return {"pred": label, "proba": float(proba_row[best_idx]), "all_probas": all_probas}
                except Exception as e:
                    print(f"Numeric-fallback prediction failed: {e}")
            # If still none, return None
            return None
        else:
            label, proba, all_probas = out
            return {"pred": label, "proba": proba, "all_probas": all_probas}
    except Exception as e:
        print(f"Error in SQLi dialect prediction: {e}")
        return None

def test_sqli_dialect_classifier():
    """Light-weight smoke test printing predictions for common errors."""
    print("🧪 Testing SQLi Dialect Classifier...")
    tests = [
        ("MySQL", "You have an error in your SQL syntax", {"content-type": "text/html"}, 500),
        ("PostgreSQL", "ERROR: syntax error at or near", {"content-type": "text/html"}, 500),
        ("MSSQL", "Unclosed quotation mark after the character string.", {"content-type": "text/html"}, 500),
        ("SQLite", "SQLiteException: no such table", {"content-type": "text/html"}, 500),
        ("Unknown", "Database error occurred", {"content-type": "text/html"}, 500),
    ]
    for name, txt, hdrs, code in tests:
        out = predict_sqli_dialect(txt, hdrs, code)
        if out:
            print(f"  {name}: {out['pred']} (p={out['proba']:.3f})")
        else:
            print(f"  {name}: Prediction unavailable")

if __name__ == "__main__":
    test_sqli_dialect_classifier()

def get_dialect_ml_health() -> Dict[str, Any]:
    """Report SQLi dialect ML asset health for /healthz."""
    health: Dict[str, Any] = {
        "has_text_model": False,
        "has_vectorizer": False,
        "has_alt_model": False,
        "text_model_features": None,
        "vectorizer_features": None,
        "dims_match": None,
        "path_in_use": None,  # one of: text, alt_numeric, unavailable
        "classes": None,
    }
    try:
        loaded = load_models()
        # Presence
        health["has_text_model"] = _dialect_model is not None
        health["has_vectorizer"] = _dialect_vectorizer is not None
        health["has_alt_model"] = _alt_model is not None
        # Dims
        if _dialect_model is not None:
            health["text_model_features"] = getattr(_dialect_model, 'n_features_in_', None)
            health["classes"] = [str(c) for c in getattr(_dialect_model, 'classes_', [])] or None
        if _dialect_vectorizer is not None:
            try:
                vocab = getattr(_dialect_vectorizer, 'vocabulary_', None)
                if vocab is not None:
                    health["vectorizer_features"] = len(vocab)
            except Exception:
                pass
        if health["text_model_features"] is not None and health["vectorizer_features"] is not None:
            health["dims_match"] = health["text_model_features"] == health["vectorizer_features"]
        # Path hint
        if health["has_text_model"] and health["has_vectorizer"] and health["dims_match"]:
            health["path_in_use"] = "text"
        elif health["has_alt_model"]:
            health["path_in_use"] = "alt_numeric"
        else:
            health["path_in_use"] = "unavailable"
    except Exception as e:
        health["error"] = str(e)
    return health
