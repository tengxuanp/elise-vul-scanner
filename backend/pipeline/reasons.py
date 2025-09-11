"""
Evidence "Why" reason mapping for accurate telemetry.
"""

from typing import List

def build_why(row: dict) -> List[str]:
    """
    Produce a short, mutually-exclusive reason set for Evidence modal.
    """
    why: List[str] = []

    if row.get("family") == "xss":
        src = row.get("rank_source")
        if src == "ctx_pool":
            # Payload came from context-seeded pool (Top-K contextual family), not ML ranker.
            why.append("ctx_guided")
        elif src == "ml_ranked":
            # Payload chosen by ML ranker from Top-K candidates.
            why.append("ml_ranked")

        # Reflection signal present (canary/DOM fragment/etc.)
        if row.get("xss_context") or row.get("xss_reflection"):
            why.append("xss_reflection")

    return why
