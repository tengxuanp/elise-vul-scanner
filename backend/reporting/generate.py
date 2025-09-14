import json, glob
from pathlib import Path
from typing import Any, Dict


def _get(d: Dict[str, Any], path: str, default: Any = None) -> Any:
    cur: Any = d
    for seg in path.split("."):
        if not isinstance(cur, dict) or seg not in cur:
            return default
        cur = cur[seg]
    return cur


def generate_markdown(job_dir: Path) -> str:
    parts = ["# Elise Scan Report"]

    # Only include evidence files, skip endpoints.json and other non-evidence files
    files = sorted(glob.glob(str(job_dir / "*_*.json")))
    if not files:
        parts.append("\n_No evidence files found for this job._")
        return "\n".join(parts)

    for fp in files:
        try:
            row = json.load(open(fp, encoding="utf-8"))
        except Exception:
            continue

        # Prefer flat fields, but fall back to nested target.* when needed
        family = row.get("family") or "unknown"
        method = row.get("method") or _get(row, "target.method", "GET")
        url = row.get("url") or _get(row, "target.url", "")
        param_in = row.get("param_in") or _get(row, "target.param_in", "")
        param = row.get("param") or _get(row, "target.param", "")

        header = f"## {family} — {method} {url} ({param_in}:{param})"
        parts.append(header)

        # CVSS line if available
        cvss = row.get("cvss")
        if isinstance(cvss, dict) and (cvss.get("base") is not None or cvss.get("vector")):
            base = cvss.get("base")
            vector = cvss.get("vector") or ""
            parts.append(f"- CVSS: **{base}** `{vector}`")

        # Why reasons
        why = row.get("why") or []
        if isinstance(why, list) and why:
            parts.append(f"- Why: {', '.join(map(str, why))}")

        # Add SQLi/XSS details if present
        if family == "sqli":
            dialect = row.get("sqli_dialect") or _get(row, "sqli_details.dialect_hint")
            if dialect:
                parts.append(f"- SQLi Dialect: `{dialect}`")
        if family == "xss":
            ctx = row.get("xss_context")
            esc = row.get("xss_escaping")
            if ctx:
                parts.append(f"- XSS Context: `{ctx}`" + (f", Escaping: `{esc}`" if esc else ""))

        # Response snippet (truncate to keep report light)
        snippet = row.get("response_snippet") or row.get("response_snippet_text") or ""
        if snippet:
            parts.extend(["```http", str(snippet)[:1500], "```"])

    return "\n".join(parts)
