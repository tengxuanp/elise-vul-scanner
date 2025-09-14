#!/usr/bin/env python3
from __future__ import annotations
import argparse, json, glob, re, random, hashlib
from urllib.parse import urlparse
from collections import defaultdict, Counter
from pathlib import Path

SQLI_ERROR_PATTERNS = [
    r"you have an error in your sql syntax",
    r"warning: mysql",
    r"mysql_fetch",
    r"unclosed quotation mark after the character string",
    r"odbc.*drivers? SQL",
    r"PostgreSQL.*ERROR",
    r"org\.postgresql\.util\.PSQLException",
    r"SQLite/JDBCDriver",
    r"Microsoft OLE DB Provider for ODBC Drivers",
    r"ORA-\d{5}",
    r"SQL syntax.*near",
    r"unterminated quoted string",
]
SQLI_ERROR_RE = re.compile("|".join(SQLI_ERROR_PATTERNS), re.I)

def short_hash(s: str) -> str:
    return hashlib.sha1((s or "").encode("utf-8", "ignore")).hexdigest()[:10]

def family_from_signals(row: dict) -> tuple[str, float]:
    """Return (label, confidence) from signals/heuristics."""
    sig = row.get("signals") or {}
    hits = row.get("detector_hits") or {}

    # Strong structured hits first
    sql_err = bool(hits.get("sql_error") or sig.get("sql_error"))
    booli   = bool(hits.get("boolean_sqli") or sig.get("boolean_sqli"))
    timei   = bool(hits.get("time_sqli") or sig.get("time_sqli"))
    xss_ref = bool(hits.get("xss_js") or hits.get("xss_raw") or (sig.get("reflection") or {}).get("raw") or (sig.get("reflection") or {}).get("js_context"))
    redir   = bool(hits.get("open_redirect") or sig.get("external_redirect") or (sig.get("open_redirect") or {}).get("open_redirect") is True)

    # Heuristic: response text regex for SQL errors (if captured)
    resp_text = (row.get("response_text") or row.get("verify", {}).get("body") or "")
    if not sql_err and resp_text and SQLI_ERROR_RE.search(resp_text):
        sql_err = True

    # Confidence policy
    if sql_err or booli or timei:
        return "sqli", 0.95 if sql_err else (0.9 if booli else 0.85)
    if xss_ref:
        return "xss", 0.9
    if redir:
        # external location?
        loc = (sig.get("verify") or {}).get("location") or (row.get("response_headers") or {}).get("location")
        if loc:
            try:
                host = urlparse(loc).hostname or ""
                # external if host looks non-empty and not same as request host
                req_host = urlparse(row.get("url") or "").hostname or ""
                if host and req_host and host != req_host:
                    return "redirect", 0.95
            except Exception:
                pass
        return "redirect", 0.8

    return "none", 0.6  # negative / no hit

def _entropy(s: str) -> float:
    try:
        if not s:
            return 0.0
        from math import log2
        from collections import Counter
        c = Counter(s)
        n = float(len(s))
        return -sum((v/n) * log2(v/n) for v in c.values())
    except Exception:
        return 0.0


def extract_features(row: dict) -> dict:
    req = row.get("request") or {}
    url = row.get("url") or req.get("url") or ""
    parsed = urlparse(url)
    host = parsed.hostname or ""
    path = parsed.path or "/"
    method = (row.get("method") or req.get("method") or "GET").upper()
    param = row.get("param") or row.get("target_param") or req.get("param") or ""
    payload = (row.get("payload_string") or row.get("payload") or (req.get("payload") if isinstance(req, dict) else "") or "") or ""
    ploc = (row.get("param_loc") or row.get("param_location") or "").lower()

    # Flags from payload
    p = payload.lower()
    payload_flags = {
        "has_quote": "'" in payload or '"' in payload,
        "has_angle": "<" in payload or ">" in payload,
        "has_lt_gt": ("<" in payload and ">" in payload),
        "has_and": " and " in f" {p} ",
        "has_or": " or " in f" {p} ",
        "has_union": "union" in p,
        "has_select": "select" in p,
        "has_script": "<script" in p,
        "has_urlenc_pct": "%" in payload,  # rough
        "has_event_handler": bool(re.search(r"on[a-z]+=", p)),
        "has_comment_seq": ("--" in p) or ("/*" in p and "*/" in p),
    }
    # SQL keyword count
    kw_list = ["select","union","and","or","from","where","sleep","benchmark","insert","update","delete"]
    sql_kw_hits = sum(1 for kw in kw_list if kw in p)
    # Balanced quotes heuristic
    balanced_quotes = (payload.count("'") % 2 == 0) and (payload.count('"') % 2 == 0)

    # Delta features
    d = {}
    for k in ("status_delta", "len_delta", "latency_ms_delta", "baseline_len"):
        v = row.get(k)
        if isinstance(v, (int, float)):
            d[k] = v

    # Signals as binary features
    sig = row.get("signals") or {}
    hits = row.get("detector_hits") or {}
    sig_flags = {
        "sql_error": bool(hits.get("sql_error") or sig.get("sql_error")),
        "boolean_sqli": bool(hits.get("boolean_sqli") or sig.get("boolean_sqli")),
        "time_sqli": bool(hits.get("time_sqli") or sig.get("time_sqli")),
        "xss_reflected": bool(hits.get("xss_js") or hits.get("xss_raw") or (sig.get("reflection") or {}).get("raw") or (sig.get("reflection") or {}).get("js_context")),
        "external_redirect": bool(hits.get("open_redirect") or sig.get("external_redirect") or (sig.get("open_redirect") or {}).get("open_redirect") is True),
    }

    # Response/context derived flags
    status = row.get("response_status") or row.get("status") or 0
    try:
        status = int(status)
    except Exception:
        status = 0
    status_class = status // 100
    status_flags = {f"status_class_{i}": int(status_class == i) for i in [2,3,4,5]}
    ct = (row.get("content_type") or row.get("response_headers",{}).get("content-type") or "").lower()
    ct_flags = {
        "content_type_html": int("text/html" in ct),
        "content_type_json": int("application/json" in ct)
    }
    xss_ctx = (row.get("xss_context") or "").lower()
    ctx_flags = {
        "ctx_html": int(xss_ctx in {"html","html_body"}),
        "ctx_attr": int(xss_ctx == "attr"),
        "ctx_js": int(xss_ctx in {"js","js_string"}),
    }

    # Param + payload analytics
    param_len = len(param or "")
    urlenc_ratio = (payload.count('%') / max(1, len(payload))) if payload else 0.0
    alnum = sum(ch.isalnum() for ch in payload)
    digits = sum(ch.isdigit() for ch in payload)
    symbols = sum(not ch.isalnum() and not ch.isspace() for ch in payload)
    n = max(1, len(payload))
    alnum_ratio = alnum / n
    digit_ratio = digits / n
    symbol_ratio = symbols / n
    double_encoded_hint = int('%25' in p or '%%' in p)
    entropy = _entropy(payload)

    return {
        "host": host,
        "path": path,
        "method": method,
        "param": param,
        "param_loc": ploc or ("query" if "?" in url else ""),
        "payload_hash": short_hash(payload),
        "payload_len": len(payload),
        "param_len": param_len,
        "alnum_ratio": alnum_ratio,
        "digit_ratio": digit_ratio,
        "symbol_ratio": symbol_ratio,
        "url_encoded_ratio": urlenc_ratio,
        "double_encoded_hint": double_encoded_hint,
        "shannon_entropy": entropy,
        "has_quote": int(payload_flags["has_quote"]),
        "has_angle": int(payload_flags["has_angle"]),
        "has_lt_gt": int(payload_flags["has_lt_gt"]),
        "has_script_tag": int(payload_flags["has_script"]),
        "has_event_handler": int(payload_flags["has_event_handler"]),
        "sql_kw_hits": int(sql_kw_hits),
        "balanced_quotes": int(balanced_quotes),
        "has_comment_seq": int(payload_flags["has_comment_seq"]),
        # Probe-style features expected by infer_ranker
        "probe_sql_error": int(sig_flags["sql_error"]),
        "probe_timing_delta_gt2s": int((row.get("latency_ms_delta") or 0) >= 2000),
        "probe_reflection_html": int(ctx_flags["ctx_html"] and sig_flags["xss_reflected"]),
        "probe_reflection_js": int(ctx_flags["ctx_js"] and sig_flags["xss_reflected"]),
        "probe_redirect_location_reflects": int(sig_flags["external_redirect"]),
        **status_flags,
        **ct_flags,
        **ctx_flags,
        **d,
    }

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in-glob", required=True, help='e.g. "data/jobs/**/results/evidence.jsonl"')
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--min-conf", type=float, default=0.0, help="drop labels below this confidence")
    ap.add_argument("--seed", type=int, default=7)
    args = ap.parse_args()
    random.seed(args.seed)

    outdir = Path(args.out_dir)
    outdir.mkdir(parents=True, exist_ok=True)

    files = sorted(glob.glob(args.in_glob, recursive=True))
    if not files:
        print("No files matched", args.in_glob)
        return

    rows = []
    for f in files:
        # Support both NDJSON (.jsonl) and one-JSON-per-file (.json)
        try:
            if f.endswith('.jsonl'):
                with open(f, "r", encoding="utf-8", errors="ignore") as fh:
                    for line in fh:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            obj = json.loads(line)
                        except Exception:
                            continue
                        rows.append(obj)
            elif f.endswith('.json'):
                try:
                    obj = json.loads(Path(f).read_text(encoding='utf-8', errors='ignore'))
                    rows.append(obj)
                except Exception:
                    continue
            else:
                # Default to NDJSON behavior
                with open(f, "r", encoding="utf-8", errors="ignore") as fh:
                    for line in fh:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            obj = json.loads(line)
                        except Exception:
                            continue
                        rows.append(obj)
        except Exception:
            continue

    # de-dup by (host,path,method,param,payload_hash)
    seen = set()
    examples = []
    per_host = defaultdict(list)

    for r in rows:
        # Map evidence schema -> expected fields
        if 'signals' not in r and 'probe_signals' in r:
            r['signals'] = r.get('probe_signals')
        if 'url' not in r and r.get('target') and isinstance(r['target'], dict):
            r['url'] = r['target'].get('url')
            r['method'] = r['target'].get('method', r.get('method','GET'))
            r['param'] = r['target'].get('param', r.get('param',''))
        feats = extract_features(r)
        y, conf = family_from_signals(r)
        if conf < args.min_conf:
            continue
        key = (feats["host"], feats["path"], feats["method"], feats["param"], feats["payload_hash"])
        if key in seen:
            continue
        seen.add(key)
        ex = {
            "x": feats,             # features for the ranker
            "y": y,                 # label: sqli/xss/redirect/none
            "confidence": conf,     # optional training weight
        }
        examples.append(ex)
        per_host[feats["host"]].append(ex)

    # Balance: cap per-host positives to avoid one noisy app dominating
    capped = []
    for host, items in per_host.items():
        # small cap – tune as needed
        keep = []
        by_label = defaultdict(list)
        for it in items:
            by_label[it["y"]].append(it)
        for lab, li in by_label.items():
            cap = 400 if lab == "none" else 300
            if len(li) > cap:
                random.shuffle(li)
                li = li[:cap]
            keep.extend(li)
        capped.extend(keep)

    # Split by host
    hosts = sorted(per_host.keys())
    random.shuffle(hosts)
    n = len(hosts)
    train_hosts = set(hosts[: int(n * 0.7)])
    dev_hosts   = set(hosts[int(n * 0.7): int(n * 0.85)])
    test_hosts  = set(hosts[int(n * 0.85):])

    def bucket(ex):
        h = ex["x"]["host"]
        if h in train_hosts: return "train"
        if h in dev_hosts:   return "dev"
        return "test"

    out_path = outdir / "ranker_dataset.jsonl"
    with open(out_path, "w", encoding="utf-8") as out:
        for ex in capped:
            ex["split"] = bucket(ex)
            out.write(json.dumps(ex, ensure_ascii=False) + "\n")

    # Tiny summary
    counts = Counter((ex["split"], ex["y"]) for ex in capped)
    summary_path = outdir / "summary.csv"
    labels = ["sqli", "xss", "redirect", "none"]
    with open(summary_path, "w", encoding="utf-8") as fh:
        fh.write("split," + ",".join(labels) + ",total\n")
        for split in ["train", "dev", "test"]:
            row_total = 0
            parts = []
            for lab in labels:
                c = counts[(split, lab)]
                parts.append(str(c))
                row_total += c
            fh.write(split + "," + ",".join(parts) + f",{row_total}\n")

    print(f"Wrote {out_path}")
    print(f"Wrote {summary_path}")

if __name__ == "__main__":
    main()
