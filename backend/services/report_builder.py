# backend/services/report_builder.py
from __future__ import annotations

import json
import statistics
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


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
                line = line.strip()
                if not line:
                    continue
                try:
                    out.append(json.loads(line))
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
    if any(x in p for x in (" or 1=1", "'--", "\"--")):
        return "sqli"
    return "unknown"


def _coerce_finding(job_id: str, row: Dict[str, Any]) -> Optional[Finding]:
    try:
        # Engine-normalized rows (type == "finding") from core
        method = str(row.get("request", {}).get("method") or row.get("method") or "GET")
        url = str(row.get("request", {}).get("url") or row.get("url") or "")
        param = row.get("request", {}).get("param") or row.get("param")
        family = row.get("payload_family") or row.get("family") or "unknown"
        payload_id = str(row.get("payload_id")) if row.get("payload_id") is not None else None
        payload = row.get("payload")

        conf = float(row.get("confidence") or 0.0)
        status = row.get("response", {}).get("status") or row.get("status")
        rh = row.get("response_hash")
        rsnip = row.get("response_snippet")

        signals = row.get("signals") or {}
        req_meta = row.get("request") or {}
        resp_meta = row.get("response") or {}

        return Finding(
            job_id=job_id,
            method=method,
            url=url,
            param=(param if isinstance(param, str) else None),
            family=family,
            payload_id=payload_id,
            payload=(payload if isinstance(payload, str) else None),
            confidence=conf,
            status=(int(status) if isinstance(status, int) or (isinstance(status, str) and status.isdigit()) else None),
            response_hash=(str(rh) if rh else None),
            response_snippet=(str(rsnip) if rsnip else None),
            signals=signals if isinstance(signals, dict) else {},
            request_meta=req_meta if isinstance(req_meta, dict) else {},
            response_meta=resp_meta if isinstance(resp_meta, dict) else {},
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
        # Prefer high-signal entries; otherwise include attempt entries with high confidence
        typ = row.get("type")
        if typ not in {"finding", "attempt"}:
            continue
        f = _coerce_finding(job_id, row)
        if not f:
            continue
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
            return int(statistics.median([int(s) for s in samples if isinstance(s, (int, float))]))
    except Exception:
        pass
    # fallback to single elapsed
    try:
        return int((f.response_meta or {}).get("elapsed_ms"))
    except Exception:
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
    widths = [max(len(str(cell)) for cell in col) for col in zip(*rows)]
    def fmt_row(r: List[Any]) -> str:
        return "| " + " | ".join(str(c).ljust(w) for c, w in zip(r, widths)) + " |"
    header = fmt_row(rows[0])
    sep = "| " + " | ".join("-" * w for w in widths) + " |"
    body = "\n".join(fmt_row(r) for r in rows[1:])
    return "\n".join([header, sep, body])


def _build_markdown(job_id: str, crawl: Dict[str, Any], findings: List[Finding], cats: Optional[Dict[str, Any]]) -> str:
    target = crawl.get("target") or crawl.get("target_url") or "unknown"
    started = crawl.get("started_at") or ""
    generated = _now_iso()
    summary = _group_counts(findings)

    # --- Top findings table ---
    top = _top_n(findings, n=15)
    top_rows: List[List[str]] = [
        ["#","Severity","Conf","Family","Method","URL","Param","Status","Latency(ms)","Snippet"]
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
            str(f.status or ""),
            str(_median_latency_ms(f) or ""),
            _short(f.response_snippet, 120),
        ])
    top_md = _mk_table(top_rows) if len(top_rows) > 1 else "_No findings._"

    # --- Category counts (if present) ---
    cat_md = ""
    if isinstance(cats, dict) and isinstance(cats.get("summary_counts"), dict):
        cc = cats["summary_counts"]
        cat_rows = [["Group","Count"]]
        for k in sorted(cc.keys()):
            cat_rows.append([k, str(cc[k])])
        cat_md = _mk_table(cat_rows)

    fam_counts = summary["by_family"]
    sev_counts = summary["by_severity"]

    md = []
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
    job_dir = JOBS_DIR / job_id
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
        sys.exit(1)
    jid = sys.argv[1]
    out = build_report(jid)
    print(f"Wrote report for job '{jid}' to {RESULTS_DIR / jid}/report.(json|md)")
