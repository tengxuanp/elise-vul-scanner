# backend/synth/synth_to_evidence.py
from __future__ import annotations
import argparse, json
from pathlib import Path

# Canonical payload strings per payload_id (keep stable!)
PAYLOAD_BODIES = {
    # ---- XSS ----
    "xss.oneliner.img_onerror": '<img src=x onerror=alert(1)>',
    "xss.oneliner.svg_onload":  '<svg onload=alert(1)>',
    "xss.oneliner.body_onload": '<body onload=alert(1)>',
    "xss.attr.breakout.quote":  '" onmouseover=alert(1) x="',
    "xss.attr.breakout.space":  " onclick=alert(1) ",
    "xss.attr.href_jsurl":      "javascript:alert(1)",
    "xss.dom.script_injection": "</script><script>alert(1)</script>",
    "xss.dom.event_handler":    '<div id=x onclick=alert(1)>x</div>',
    "xss.js.url_javascript":    "javascript:prompt(1)",
    "xss.html.tag_echo":        "<b>test</b>",
    "xss.polyglot.svg_data":    '<svg><animate onbegin=alert(1) attributeName=x></animate></svg>',
    "xss.template.mustache":    "{{7*7}}",
    # ---- SQLi ----
    "sqli.union.null":          "' UNION SELECT NULL-- -",
    "sqli.union.select_1":      "' UNION SELECT 1-- -",
    "sqli.boolean_true":        "' OR 1=1-- -",
    "sqli.boolean_false":       "' AND 1=2-- -",
    "sqli.time.sleep5":         "' OR SLEEP(5)-- -",
    "sqli.time.benchmark":      "' OR benchmark(5000000,MD5(1))-- -",
    "sqli.error.oracle":        "' || (SELECT 1 FROM DUAL WHERE 1=utl_inaddr.get_host_name(1)) || '",
    "sqli.error.mysql":         '" AND (SELECT 1 FROM (SELECT COUNT(*), CONCAT(0x3a,(SELECT version()),0x3a,FLOOR(RAND(0)*2)) x FROM information_schema.tables GROUP BY x)a)-- -',
    "sqli.stack_comment":       "'))/*",
    "sqli.inline_comment":      "'/**/OR/**/1=1-- -",
    "sqli.numeric_or1eq1":      "1 OR 1=1",
    "sqli.like_wildcards":      "%' OR '%'='",
    # ---- Redirect ----
    "redir.http.full":          "http://evil.com",
    "redir.https.full":         "https://evil.com",
    "redir.protocol_relative":  "//evil.com",
    "redir.path_scheme_encoded":"%2f%2fevil.com",
    "redir.js_location":        "javascript:window.location='https://evil.com'",
    "redir.base64_url":         "aHR0cHM6Ly9ldmlsLmNvbQ==",
    "redir.double_urlencode":   "%252f%252fevil.com",
    "redir.open_redirect_param":"https://evil.com/",
    "redir.crlf_injection":     "https://evil.com%0d%0aSet-Cookie:evil=1",
}

def convert_one(in_path: Path, out_path: Path):
    with in_path.open("r", encoding="utf-8") as fin, out_path.open("w", encoding="utf-8") as fout:
        for line in fin:
            if not line.strip(): continue
            r = json.loads(line)
            fam = r.get("family")
            ep  = r.get("endpoint", {})
            prm = r.get("param", {})
            pid = r.get("payload_id")
            label = int(r.get("label", 0))

            payload = PAYLOAD_BODIES.get(pid, pid or "")

            # Synthesize detector hits from label + family
            det = {}
            if label >= 2:
                if fam == "xss":
                    det = {"xss_js": True}
                elif fam == "sqli":
                    det = {"boolean_sqli": True}
                elif fam == "redirect":
                    det = {"open_redirect": {"external": True}}
            elif label == 1:
                # Weak / suspicious signals
                det = {}
            else:
                det = {}

            rec = {
                "type": "attempt",
                "payload": payload,
                "payload_string": payload,
                "payload_family_used": fam,
                "url": ep.get("url"),
                "param": prm.get("name"),
                "method": ep.get("method", "GET"),
                "content_type": prm.get("content_type"),
                "headers": {},

                # Signals used by scorer for soft labels (only when label==1)
                "detector_hits": det,
                "status_delta": 1 if label == 1 else 0,
                "len_delta": 350 if label == 1 else 0,
                "latency_ms_delta": 900 if (label == 1 and fam == "sqli") else 0,
                "ml": {"p": 0.7 if label == 1 else 0.0},
            }
            fout.write(json.dumps(rec, ensure_ascii=False) + "\n")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="inp", required=True, help="input synth JSONL (e.g., data/ml/synth/synth_train.jsonl)")
    ap.add_argument("--out", dest="outp", required=True, help="output evidence JSONL")
    args = ap.parse_args()
    convert_one(Path(args.inp), Path(args.outp))
    print("wrote", args.outp)

if __name__ == "__main__":
    main()
