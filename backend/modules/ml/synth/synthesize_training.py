from __future__ import annotations
import json, glob, re, random, pathlib
from collections import Counter
from typing import List, Dict, Any
import pandas as pd

FAMILIES = ["sqli","xss","redirect","base"]

def path_tokens(u: str) -> List[str]:
    toks = [t for t in re.split(r"[/\\/_\\-\\.\\?=&:#]+", u.lower()) if t]
    return toks[:8]

def param_tokens(p: str) -> List[str]:
    return re.findall(r"[a-z0-9]+", (p or "").lower())

PRIORS = {
    "sqli": {"id","uid","user","prod","item","cat","page","sort","order"},
    "xss": {"q","query","search","term","msg","name","email","comment"},
    "redirect": {"return","return_to","next","url","dest","target","to","redir"},
}
def prior_family(param: str) -> str:
    p = (param or "").lower()
    for fam, keys in PRIORS.items():
        if any(k in p for k in keys):
            return fam
    return "base"

def from_logs(glob_pattern: str) -> pd.DataFrame:
    rows = []
    for fp in glob.glob(glob_pattern, recursive=True):
        try:
            f = open(fp, "r", encoding="utf-8", errors="ignore")
        except Exception:
            continue
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except Exception:
                continue
            url = ev.get("url") or ev.get("target") or ""
            method = ev.get("method","GET")
            param = ev.get("param") or ev.get("param_name") or ""
            fam_used = (ev.get("payload_family_used")
                        or ev.get("family") or prior_family(param))
            pos = bool(ev.get("signals",{}).get("sql_error") or
                       ev.get("signals",{}).get("xss_reflected") or
                       ev.get("signals",{}).get("boolean_sqli") or
                       (abs(ev.get("len_delta",0))>200))
            rows.append({
                "url": url, "method": method, "param": param,
                "y_family": fam_used, "y_useful": int(pos),
                "x_path": " ".join(path_tokens(url)),
                "x_param": " ".join(param_tokens(param))
            })
    return pd.DataFrame(rows)

def synth(n: int=2000) -> pd.DataFrame:
    rows=[]
    for _ in range(n):
        fam = random.choices(FAMILIES, weights=[3,3,1,1], k=1)[0]
        pri = random.choice(list(PRIORS.get(fam, {"v"}))) if fam!="base" else "v"
        param = f"{pri}{random.randint(1,99)}"
        path = f"shop/{'prod' if fam=='sqli' else 'search' if fam=='xss' else 'login'}/view"
        rows.append({
            "url": f"https://ex.com/{path}?{param}=x",
            "method": random.choice(["GET","POST"]),
            "param": param,
            "y_family": fam,
            "y_useful": int(fam in {"sqli","xss"}),
            "x_path": " ".join(path_tokens(path)),
            "x_param": " ".join(param_tokens(param))
        })
    return pd.DataFrame(rows)

def build(out_dir="backend/modules/ml/data",
          glob_pattern="data/jobs/**/results/evidence.jsonl"):
    pathlib.Path(out_dir).mkdir(parents=True, exist_ok=True)
    df_logs = from_logs(glob_pattern)
    df_syn  = synth() if len(df_logs)<500 else pd.DataFrame()
    df = pd.concat([df_logs, df_syn], ignore_index=True)
    df["text"] = (df["method"].astype(str)+" "+df["x_path"]+" "+df["x_param"]).str.strip()
    df = df[(df["y_family"].isin(FAMILIES)) & df["text"].str.len().gt(0)]
    out_fp = f"{out_dir}/family_corpus.csv"
    df.to_csv(out_fp, index=False)
    print("Saved", len(df), "rows to", out_fp)

if __name__ == "__main__":
    build()
