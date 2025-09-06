# backend/services/report_builder.py
from __future__ import annotations

import json
import statistics
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

# ------------------------------- paths -------------------------------

REPO_ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = REPO_ROOT / "data"
JOBS_DIR = DATA_DIR / "jobs"
RESULTS_DIR = DATA_DIR / "results"

for _p in (JOBS_DIR, RESULTS_DIR):
    _p.mkdir(parents=True, exist_ok=True)


# ---------------------------- data classes ---------------------------

@dataclass
class Finding:
    job_id: str
    method: str
    url: str
    param: Optional[str]
    family: str
    payload_id: Optional[str]
    payload: Optional[str]
    confidence: float
    status: Optional[int]
    response_hash: Optional[str]
    response_snippet: Optional[str]
    signals: Dict[str, Any]
    request_meta: Dict[str, Any]
    response_meta: Dict[str, Any]


# ---------------------------- file loaders ---------------------------

def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _read_jsonl(path: Path) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    try:
        with path.open("r", encoding="utf-8") as f:
            for line in f:
                s = line.strip()
                if not s:
                    continue
                try:
                    row = json.loads(s)
                    if isinstance(row, dict):
                        out.append(row)
                except Exception:
                    # skip broken lines
                    continue
    except Exception:
        pass
    return out


def _find_evidence_path(job_id: str) -> Optional[Path]:
    # Preferred: data/jobs/<job>/results/evidence.jsonl
    p = JOBS_DIR / job_id / "results" / "evidence.jsonl"
    if p.exists():
        return p
    # Fallback: any *.jsonl in results directory for the job
    rdir = JOBS_DIR / job_id / "results"
    if rdir.exists():
        for cand in sorted(rdir.glob("*.jsonl")):
            return cand
    return None


def _load_crawl_blob(job_id: str) -> Dict[str, Any]:
    p = JOBS_DIR / job_id / "crawl_result.json"
    return _read_json(p) or {}


def _host_from_url(u: str) -> str:
    try:
        from urllib.parse import urlparse
        return (urlparse(u).netloc or "").replace(":", "_")
    except Exception:
        return ""


def _load_categories(job_id: str, target_url: Optional[str]) -> Optional[Dict[str, Any]]:
    host = _host_from_url(target_url or "")
    if not host:
        return None
    p = RESULTS_DIR / host / "categorized_endpoints.json"
    return _read_json(p)


# --------------------------- summarization ---------------------------

def _severity_from(f: Finding) -> str:
    # Signals shortcut for high severity
    sig = f.signals or {}
    redir = ((sig.get("open_redirect") or {}) if isinstance(sig.get("open_redirect"), dict) else {})
    login = ((sig.get("login") or {}) if isinstance(sig.get("login"), dict) else {})
    reflection = ((sig.get("reflection") or {}) if isinstance(sig.get("reflection"), dict) else {})
    sqlerr = bool(sig.get("sql_error"))

    if redir.get("open_redirect") or login.get("login_success"):
        return "high"
    if sqlerr or reflection.get("js_context"):
        return "high"

    # Confidence-driven
    c = f.confidence or 0.0
    if c >= 0.9:
        return "high"
    if c >= 0.6:
        return "medium"
    return "low"


def _family_of(f: Finding) -> str:
    fam = (f.family or "").strip().lower()
    if fam:
        return fam
    # Derive from payload if missing
    p = (f.payload or "").lower()
    if any(x in p for x in ("<script", "onerror=", "onload=", "alert(")):
        return "xss"
    if any(x in p for x in ("http://", "https://", "//")):
        return "redirect"
    if any(x in p for x in (" or 1=1", "'--", "\"--", "union select", "sleep(")):
        return "sqli"
    return "unknown"


def _coerce_finding(job_id: str, row: Dict[str, Any]) -> Optional[Finding]:
    """
    Normalize heterogeneous rows from either the verification-first core engine
    (type == 'finding') or legacy/ffuf paths (type may be 'attempt' or omitted).
    """
    try:
        # Request side (prefer canonical request.*)
        req = row.get("request") or row.get("request_meta") or {}
        method = str(req.get("method") or row.get("method") or "GET")
        url = str(req.get("url") or row.get("url") or "")
        param = req.get("param") or row.get("param")

        # Family / payload identifiers
        family = (
            row.get("payload_family")
            or row.get("family")
            or (row.get("ranker_meta") or {}).get("family_chosen")
            or "unknown"
        )
        payload_id = str(row.get("payload_id")) if row.get("payload_id") is not None else None
        payload = row.get("payload")

        # Confidence
        conf = float(row.get("confidence") or (row.get("ranker_meta") or {}).get("ranker_score") or 0.0)

        # Response/meta & status (prefer canonical response.*)
        resp = row.get("response") or row.get("response_meta") or {}
        status = resp.get("status") or row.get("status") or None

        # Legacy verify blob may carry status/redirect info
        verify = (row.get("signals") or {}).get("verify") or row.get("verify") or {}
        if status is None and isinstance(verify, dict):
            status = verify.get("status")

        # Response snippet/hash if present (non-fatal if absent)
        rh = row.get("response_hash")
        rsnip = row.get("response_snippet") or resp.get("snippet")

        # Signals — keep as dict
        signals = row.get("signals") or {}
        if not isinstance(signals, dict):
            signals = {}

        # Ensure verify info is reflected under signals.open_redirect.* for the report
        if isinstance(verify, dict):
            od = signals.setdefault("open_redirect", {}) if isinstance(signals, dict) else {}
            if isinstance(od, dict):
                od.setdefault("location", verify.get("location"))
                # may fill location_host on the UI later

        return Finding(
            job_id=job_id,
            method=method,
            url=url,
            param=(param if isinstance(param, str) else None),
            family=str(family),
            payload_id=payload_id,
            payload=(payload if isinstance(payload, str) else None),
            confidence=conf,
            status=(int(status) if isinstance(status, (int, float)) else None),
            response_hash=(str(rh) if rh else None),
            response_snippet=(str(rsnip) if rsnip else None),
            signals=signals,
            request_meta=req if isinstance(req, dict) else {},
            response_meta=resp if isinstance(resp, dict) else {},
        )
    except Exception:
        return None


def _load_findings(job_id: str) -> List[Finding]:
    p = _find_evidence_path(job_id)
    if not p:
        return []
    raw = _read_jsonl(p)
    out: List[Finding] = []
    for row in raw:
        if not isinstance(row, dict):
            continue
        typ = row.get("type")
        if typ not in {"finding", "attempt", None}:
            continue
        f = _coerce_finding(job_id, row)
        if not f:
            continue
        # Keep definitive findings or high-confidence attempts
        if typ == "finding" or (f.confidence >= 0.6):
            out.append(f)
    return out


def _group_counts(findings: List[Finding]) -> Dict[str, Any]:
    fam_counts: Dict[str, int] = {}
    sev_counts: Dict[str, int] = {"high": 0, "medium": 0, "low": 0}
    for f in findings:
        fam = _family_of(f)
        fam_counts[fam] = fam_counts.get(fam, 0) + 1
        sev_counts[_severity_from(f)] += 1
    return {"by_family": fam_counts, "by_severity": sev_counts, "total": len(findings)}


def _top_n(findings: List[Finding], n: int = 15) -> List[Finding]:
    return sorted(findings, key=lambda x: (x.confidence or 0.0), reverse=True)[: max(0, n)]


def _median_latency_ms(f: Finding) -> Optional[int]:
    try:
        samples = (f.response_meta or {}).get("timing_samples_ms")
        if isinstance(samples, list) and samples:
            vals = [float(s) for s in samples if isinstance(s, (int, float))]
            if vals:
                return int(statistics.median(vals))
    except Exception:
        pass
    # fallback to single elapsed
    try:
        v = (f.response_meta or {}).get("elapsed_ms")
        if isinstance(v, (int, float)):
            return int(v)
    except Exception:
        pass
    return None


# ----------------------------- report core ----------------------------

def _now_iso() -> str:
    return datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


def _short(s: Optional[str], limit: int = 180) -> str:
    if not s:
        return ""
    s = s.replace("\r", " ").replace("\n", " ")
    return s if len(s) <= limit else (s[: limit - 1] + "…")


def _mk_table(rows: List[List[str]]) -> str:
    """
    Render a simple GitHub-flavored Markdown table. Assumes header is rows[0].
    """
    if not rows:
        return ""
    # Defensive: ensure all rows have the same width as header
    width = len(rows[0])
    norm_rows = [r[:width] + [""] * (width - len(r)) if len(r) < width else r[:width] for r in rows]
    widths = [max(len(str(cell)) for cell in col) for col in zip(*norm_rows)]

    def fmt_row(r: List[Any]) -> str:
        cells = [str(c) for c in r]
        return "| " + " | ".join(s.ljust(w) for s, w in zip(cells, widths)) + " |"

    header = fmt_row(norm_rows[0])
    sep = "| " + " | ".join("-" * w for w in widths) + " |"
    body = "\n".join(fmt_row(r) for r in norm_rows[1:])
    return "\n".join([header, sep, body])


def _build_markdown(job_id: str, crawl: Dict[str, Any], findings: List[Finding], cats: Optional[Dict[str, Any]]) -> str:
    target = crawl.get("target") or crawl.get("target_url") or "unknown"
    started = crawl.get("started_at") or ""
    generated = _now_iso()
    summary = _group_counts(findings)

    # --- Top findings table ---
    top = _top_n(findings, n=15)
    top_rows: List[List[str]] = [
        ["#", "Severity", "Conf", "Family", "Method", "URL", "Param", "Status", "Latency(ms)", "Snippet"]
    ]
    for i, f in enumerate(top, start=1):
        top_rows.append([
            str(i),
            _severity_from(f),
            f"{(f.confidence or 0.0):.2f}",
            _family_of(f),
            f.method,
            f.url,
            f.param or "",
            (str(f.status) if f.status is not None else ""),
            (str(_median_latency_ms(f)) if _median_latency_ms(f) is not None else ""),
            _short(f.response_snippet, 120),
        ])
    top_md = _mk_table(top_rows) if len(top_rows) > 1 else "_No findings._"

    # --- Category counts (if present) ---
    cat_md = ""
    if isinstance(cats, dict) and isinstance(cats.get("summary_counts"), dict):
        cc = cats["summary_counts"]
        cat_rows = [["Group", "Count"]]
        for k in sorted(cc.keys()):
            try:
                v = int(cc[k])
            except Exception:
                v = cc[k]
            cat_rows.append([k, str(v)])
        cat_md = _mk_table(cat_rows)

    fam_counts = summary["by_family"]
    sev_counts = summary["by_severity"]

    md: List[str] = []
    md.append(f"# Scan Report — Job `{job_id}`")
    md.append("")
    md.append(f"- Target: **{target}**")
    md.append(f"- Generated: **{generated}**")
    if started:
        md.append(f"- Crawl started at: **{started}**")
    md.append("")
    md.append("## Summary")
    md.append("")
    md.append(f"- Total findings considered: **{summary['total']}**")
    md.append(f"- By severity: **high={sev_counts.get('high',0)}**, **medium={sev_counts.get('medium',0)}**, **low={sev_counts.get('low',0)}**")
    if fam_counts:
        md.append("- By family: " + ", ".join(f"`{k}`={v}" for k, v in sorted(fam_counts.items())))
    md.append("")
    if cat_md:
        md.append("## Endpoint Categories (from crawl)")
        md.append("")
        md.append(cat_md)
        md.append("")
    md.append("## Top Findings")
    md.append("")
    md.append(top_md)
    md.append("")
    md.append("> Note: Severity is derived from engine signals (open redirect/login oracle/JS reflection/SQL errors) and confidence score heuristics.")
    return "\n".join(md)


# ---------------------------- public API -----------------------------

def build_report(job_id: str) -> Dict[str, Any]:
    """
    Build a structured report (JSON + Markdown) for a given job.
    Writes to data/results/<job_id>/report.json and report.md
    Returns the JSON payload.
    """
    out_dir = RESULTS_DIR / job_id
    out_dir.mkdir(parents=True, exist_ok=True)

    crawl = _load_crawl_blob(job_id) or {}
    target_url = crawl.get("target") or crawl.get("target_url")
    cats = _load_categories(job_id, target_url)
    raw_findings = _load_findings(job_id)

    # JSON-friendly findings
    def _f_to_dict(f: Finding) -> Dict[str, Any]:
        return {
            "job_id": f.job_id,
            "method": f.method,
            "url": f.url,
            "param": f.param,
            "family": _family_of(f),
            "payload_id": f.payload_id,
            "payload": f.payload,
            "confidence": f.confidence,
            "status": f.status,
            "response_hash": f.response_hash,
            "response_snippet": f.response_snippet,
            "signals": f.signals,
            "request_meta": f.request_meta,
            "response_meta": f.response_meta,
            "severity": _severity_from(f),
            "latency_ms": _median_latency_ms(f),
        }

    payload: Dict[str, Any] = {
        "job_id": job_id,
        "generated_at": _now_iso(),
        "target": target_url,
        "summary": _group_counts(raw_findings),
        "top_findings": [_f_to_dict(f) for f in _top_n(raw_findings, 50)],
        "all_findings": [_f_to_dict(f) for f in raw_findings],  # keep full list for machine use
        "categories": cats or {},
    }

    # Write JSON + Markdown
    (out_dir / "report.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")
    md = _build_markdown(job_id, crawl, raw_findings, cats)
    (out_dir / "report.md").write_text(md, encoding="utf-8")

    return payload


# ----------------------------- CLI helper ----------------------------

if __name__ == "__main__":  # pragma: no cover
    import sys
    if len(sys.argv) != 2:
        print("Usage: python -m backend.services.report_builder <job_id>")
        raise SystemExit(1)
    jid = sys.argv[1]
    out = build_report(jid)
    print(f"Wrote report for job '{jid}' to {RESULTS_DIR / jid}/report.(json|md)")
