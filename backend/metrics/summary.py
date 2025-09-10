"""
Summary metrics computation for XSS context analysis.
"""

def _to_int(x, default=0):
    """Safely convert to int with default."""
    try:
        return int(x)
    except Exception:
        return default

def finalize_xss_context_metrics(meta: dict, rows: list[dict], *, ui_top_k_default: int | None = None) -> dict:
    """
    Compute:
      - baseline: sum of Top-K we *would* try for each ctx_pool positive
      - used:     sum of actual attempts used (attempt_idx if present, else 1 per hit)
      - attempts_saved = baseline - used (>= 0)
    Also preserves xss_first_hit_attempts_ctx counted during row writes.
    """
    meta = dict(meta or {})

    ctx_hits = [r for r in rows if r.get("family") == "xss" and r.get("rank_source") == "ctx_pool"]

    top_k_default = _to_int(ui_top_k_default or meta.get("top_k_default") or 0)

    # per-row Top-K (prefer recorded value, fallback to UI default)
    baseline = sum(_to_int(r.get("top_k_used"), top_k_default) for r in ctx_hits)

    # actual attempts used:
    # prefer attempt_idx if the pipeline records it; otherwise assume first-hit = 1 per ctx hit
    used = 0
    for r in ctx_hits:
        idx = r.get("attempt_idx")
        used += max(1, _to_int(idx, 1))

    # as an extra safety net, if used still zero but we have the ctx counter, use that
    if used == 0:
        used = _to_int(meta.get("xss_first_hit_attempts_ctx"), 0)

    saved = max(0, baseline - used)

    meta["xss_first_hit_attempts_baseline"] = baseline
    meta["xss_first_hit_attempts_used"] = used
    # keep previously counted ctx counter
    meta["xss_first_hit_attempts_ctx"] = _to_int(meta.get("xss_first_hit_attempts_ctx"), 0)
    meta["attempts_saved"] = saved
    
    return meta
