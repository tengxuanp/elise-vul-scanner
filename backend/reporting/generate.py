import json, glob
from pathlib import Path

def generate_markdown(job_dir:Path)->str:
    parts = ["# Elise Scan Report"]
    for fp in sorted(glob.glob(str(job_dir/"*.json"))):
        row = json.load(open(fp,encoding="utf-8"))
        parts += [f"## {row['family']} — {row['method']} {row['url']} ({row['param_in']}:{row['param']})",
                  f"- CVSS: **{row['cvss']['base']}** `{row['cvss']['vector']}`",
                  f"- Why: {', '.join(row['why'])}",
                  "```http", (row['response_snippet'] or "")[:1500], "```"]
    return "\n".join(parts)