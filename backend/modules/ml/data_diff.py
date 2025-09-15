from __future__ import annotations

"""
Stub classifier for data-diff based SQLi leakage detection.
Enabled behind feature flag ELISE_ENABLE_DATA_DIFF. Intended to be replaced
with a trained model; provides a conservative heuristic probability.
"""

import os
from typing import Dict, Any


def classify(features: Dict[str, Any]) -> float:
    """
    Return probability [0,1] that the diff indicates a data leak.
    Conservative heuristic used when ELISE_ENABLE_DATA_DIFF=1.
    """
    if os.getenv("ELISE_ENABLE_DATA_DIFF", "0") != "1":
        return 0.0
    # Features expected:
    #  - response_len_delta
    #  - json_key_gain
    #  - html_tag_gain
    #  - both_json
    dlen = float(features.get("response_len_delta", 0.0) or 0.0)
    key_gain = int(features.get("json_key_gain", 0) or 0)
    tag_gain = int(features.get("html_tag_gain", 0) or 0)
    both_json = bool(features.get("both_json", False))
    # Simple scoring
    score = 0.0
    if both_json and key_gain >= 2:
        score += 0.55
    if abs(dlen) > 400:
        score += 0.25
    if tag_gain >= 3:
        score += 0.20
    return min(1.0, max(0.0, score))


def prepare_training_row(attack: Dict[str, Any], control: Dict[str, Any]) -> Dict[str, Any]:
    """
    Build a training example row from two InjectionResult-like dicts.
    """
    a, c = attack, control
    both_json = bool(a.get("is_json") and c.get("is_json"))
    a_keys = set((a.get("json_top_keys") or "").split(",")) if a.get("json_top_keys") else set()
    c_keys = set((c.get("json_top_keys") or "").split(",")) if c.get("json_top_keys") else set()
    json_key_gain = len(a_keys - c_keys)
    # tag gains
    tag_gain = 0
    if a.get("html_tag_counts") and c.get("html_tag_counts"):
        for k, av in (a["html_tag_counts"] or {}).items():
            tag_gain += max(0, int(av or 0) - int((c["html_tag_counts"] or {}).get(k, 0) or 0))
    return {
        "response_len_delta": int(a.get("response_len", 0)) - int(c.get("response_len", 0)),
        "json_key_gain": json_key_gain,
        "html_tag_gain": tag_gain,
        "both_json": both_json,
        # Include originals (trimmed) for offline labeling
        "attack_is_json": bool(a.get("is_json")),
        "control_is_json": bool(c.get("is_json")),
        "attack_json_keys": a.get("json_top_keys"),
        "control_json_keys": c.get("json_top_keys"),
    }

