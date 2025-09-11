"""
Centralized telemetry recording for vulnerability assessment.
"""

def record_ctx_first_hit(job, row: dict):
    """Increment first-hit ctx counter when a ctx_pool positive lands on attempt #1."""
    try:
        if (
            row.get("family") == "xss"
            and row.get("rank_source") == "ctx_pool"
            and int(row.get("attempt_idx") or 0) == 1
        ):
            meta = job.meta or {}
            meta["xss_first_hit_attempts_ctx"] = int(meta.get("xss_first_hit_attempts_ctx", 0)) + 1
            job.meta = meta
    except Exception:
        # Telemetry must not break findings
        pass
