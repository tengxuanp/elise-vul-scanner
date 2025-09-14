"""
Summary metrics computation for XSS context analysis and SQLi dialect analysis.
"""

from typing import Optional, List, Dict, Any

def _to_int(x, default=0):
    """Safely convert to int with default."""
    try:
        return int(x)
    except Exception:
        return default

def _i(x, d=0):
    try: return int(x)
    except: return d

def compute_totals_from_rows(rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Compute totals from rows for consistency checking."""
    t = {"positive": 0, "suspected": 0, "abstain": 0, "clean": 0, "na": 0, "error": 0}
    for r in rows:
        key = (r.get("decision") or "").lower()
        if key in t:
            t[key] += 1
    t["total"] = sum(t.values())
    return t

def finalize_xss_context_metrics_robust(meta: Dict[str, Any], rows: List[Dict[str, Any]], *, xss_top_k_default: int) -> Dict[str, Any]:
    """Robust version of XSS context metrics finalization."""
    meta = dict(meta or {})
    ctx_hits = [r for r in rows if r.get("family") == "xss" and r.get("rank_source") == "ctx_pool"]

    # Baseline: sum Top-K per hit (prefer per-row top_k_used, fallback to run default)
    baseline = sum(_to_int(r.get("top_k_used"), xss_top_k_default) for r in ctx_hits)

    # Used: attempts actually consumed (prefer attempt_idx, else assume first-hit=1)
    used = 0
    for r in ctx_hits:
        used += max(1, _to_int(r.get("attempt_idx"), 1))
    if used == 0:  # safety net if attempt_idx not persisted
        used = _to_int(meta.get("xss_first_hit_attempts_ctx"), 0)

    saved = max(0, baseline - used)

    meta["xss_first_hit_attempts_baseline"] = baseline
    meta["xss_first_hit_attempts_used"] = used
    meta["attempts_saved"] = saved
    # keep the rolling counter updated elsewhere
    meta["xss_first_hit_attempts_ctx"] = _to_int(meta.get("xss_first_hit_attempts_ctx"), 0)
    return meta

def finalize_summary(job, summary: Dict[str, Any], rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Finalize summary with consistency checks and XSS context metrics."""
    # 1) Sanitize rows: don't allow XSS keys on SQL rows
    clean_rows = []
    for r in rows:
        if r.get('family') == 'sqli':
            for k in ('xss_context','xss_reflection','ctx_hint','escaping'):
                r.pop(k, None)
        clean_rows.append(r)
    
    # 2) Counters from the row table = source of truth
    table_totals = compute_totals_from_rows(clean_rows)
    summary["totals_from_rows"] = table_totals
    summary["counters_consistent"] = (table_totals.get("total") == summary.get("total"))

    # 2) XSS context metrics with correct Top-K
    plan_top_k = summary.get("top_k") or (job.meta or {}).get("xss_top_k") or 0
    meta = finalize_xss_context_metrics_robust(job.meta or {}, rows, xss_top_k_default=_to_int(plan_top_k, 0))

    # 3) SQLi dialect analysis metrics
    meta = finalize_sqli_dialect_metrics(meta, rows)

    # Optionally persist meta back to job
    summary["meta"] = meta
    job.meta = meta
    return summary

def finalize_xss_context_metrics(meta: Dict[str, Any], rows: List[Dict[str, Any]], *, ui_top_k_default: Optional[int] = None) -> Dict[str, Any]:
    """
    Compute:
      - baseline: sum of Top-K we *would* try for each ctx_pool positive
      - used:     sum of actual attempts used (attempt_idx if present, else 1 per hit)
      - attempts_saved = baseline - used (>= 0)
      - xss_rank_source_ml: number of attempts where evidence.xss.rank_source == "ml"
      - xss_context_pool_used: same as above (dedup by endpoint if needed)
      - xss_first_hit_ctx: count endpoints where first executed payload belonged to predicted context family
      - xss_first_hit_baseline: count endpoints where first payload was a baseline family
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

    # New telemetry counters
    xss_rank_source_ml = 0
    xss_context_pool_used = 0
    xss_first_hit_ctx = 0
    xss_first_hit_baseline = 0
    
    # Count ML rank source and context pool usage
    for r in rows:
        if r.get("family") == "xss":
            # Check if rank_source is "ml" from telemetry
            telemetry = r.get("telemetry", {})
            xss_telemetry = telemetry.get("xss", {})
            if xss_telemetry.get("rank_source") == "ml":
                xss_rank_source_ml += 1
                xss_context_pool_used += 1
            
            # Check first hit context vs baseline
            attempt_idx = r.get("attempt_idx", 0)
            if attempt_idx == 1:  # First attempt
                if xss_telemetry.get("context_final") in ["html", "attr", "js_string"]:
                    xss_first_hit_ctx += 1
                else:
                    xss_first_hit_baseline += 1

    meta["xss_first_hit_attempts_baseline"] = baseline
    meta["xss_first_hit_attempts_used"] = used
    # keep previously counted ctx counter
    meta["xss_first_hit_attempts_ctx"] = _to_int(meta.get("xss_first_hit_attempts_ctx"), 0)
    meta["attempts_saved"] = saved
    
    # Add new telemetry counters
    meta["xss_rank_source_ml"] = xss_rank_source_ml
    meta["xss_context_pool_used"] = xss_context_pool_used
    meta["xss_first_hit_ctx"] = xss_first_hit_ctx
    meta["xss_first_hit_baseline"] = xss_first_hit_baseline
    
    # Log telemetry summary
    print(f"XSS_TELEMETRY ml_final={meta.get('xss_final_from_ml', 0)} rs_ml={xss_rank_source_ml} used={xss_context_pool_used} saved={saved}")
    
    return meta

def finalize_sqli_dialect_metrics(meta: Dict[str, Any], rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Compute SQLi dialect analysis metrics from result rows.

    Produces into meta:
      - sqli_positives_total: count of SQLi positives
      - sqli_dialect_ml_invoked: count where sqli_dialect_source startswith "ml"
      - sqli_dialect_ml_confident: count where source startswith "ml" and proba > 0.7
      - sqli_dialect_dist: map of dialect -> count
    """
    meta = dict(meta or {})
    total = 0
    ml_invoked = 0
    ml_confident = 0
    dist: Dict[str, int] = {}

    for r in rows:
        if r.get("family") != "sqli":
            continue
        if r.get("decision") != "positive":
            continue
        total += 1
        d = (r.get("sqli_dialect") or "unknown").lower()
        dist[d] = dist.get(d, 0) + 1
        src = (r.get("sqli_dialect_source") or "").lower()
        if src.startswith("ml"):
            ml_invoked += 1
            try:
                p = float(r.get("sqli_dialect_ml_proba") or 0.0)
            except Exception:
                p = 0.0
            if p > 0.7:
                ml_confident += 1

    meta["sqli_positives_total"] = total
    meta["sqli_dialect_ml_invoked"] = ml_invoked
    meta["sqli_dialect_ml_confident"] = ml_confident
    meta["sqli_dialect_dist"] = dist
    return meta
