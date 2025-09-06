# backend/synth/gen_synth_datasets.py
from __future__ import annotations
import argparse, json, random
from pathlib import Path

random.seed(42)

# --- candidate payload IDs (stable, keep these IDs fixed) ---
XSS_PAYLOADS = [
    "xss.oneliner.img_onerror","xss.oneliner.svg_onload","xss.oneliner.body_onload",
    "xss.attr.breakout.quote","xss.attr.breakout.space","xss.attr.href_jsurl",
    "xss.dom.script_injection","xss.dom.event_handler","xss.js.url_javascript",
    "xss.html.tag_echo","xss.polyglot.svg_data","xss.template.mustache",
]
SQLI_PAYLOADS = [
    "sqli.union.null","sqli.union.select_1","sqli.boolean_true","sqli.boolean_false",
    "sqli.time.sleep5","sqli.time.benchmark","sqli.error.oracle","sqli.error.mysql",
    "sqli.stack_comment","sqli.inline_comment","sqli.numeric_or1eq1","sqli.like_wildcards",
]
REDIR_PAYLOADS = [
    "redir.http.full","redir.https.full","redir.protocol_relative","redir.path_scheme_encoded",
    "redir.js_location","redir.base64_url","redir.double_urlencode","redir.open_redirect_param",
    "redir.crlf_injection",
]

POOL = {
    "xss": ["q","query","search","s","term","callback","cb","next","return","redirect","comment","msg","content","title","desc","html"],
    "sqli": ["id","user_id","uid","pid","product_id","ref","order","page","cat","category_id","post","item","idx","num","key"],
    "redirect": ["next","return","redirect","url","target","dest","goto","continue","forward","cb","callback"],
    "neutral": ["lang","token","csrf","session","color","size","sort","filter","mode","tab"],
}

XSS_VARIANTS = ["raw","attr","js","html_reflect","none"]
SQLI_VARIANTS = ["union","boolean","time","error","none"]
REDIR_VARIANTS = ["open_external","same_host","blocked","none"]

def rand_domain():
    bases = ["example.com","test.local","shop.dev","stage.internal","api.example.org","myapp.io"]
    subs  = ["", "api", "www", "beta", "admin", "v2"]
    s = random.choice(subs)
    base = random.choice(bases)
    return (s+"."+base).strip(".")

def rand_path(depth):
    vocab = ["search","items","product","login","callback","account","orders","details","view","list","profile","redirect","page","article","feed","gateway","oauth","auth"]
    return "/" + "/".join(random.choice(vocab) for _ in range(depth))

def shape_key(method, path, q, f, j):
    return f"{method}|{path}|Q={sorted(q)}|F={sorted(f)}|J={sorted(j)}"

def tokenize_param_name(n):
    n = n.replace("-", "_")
    return [t for t in n.split("_") if t][:3]

def domain_tokens(d):
    return [p for p in d.split(".") if p and p not in ("www","api")]

def pick_variant(f):
    if f=="xss": return random.choices(XSS_VARIANTS,[0.28,0.22,0.18,0.18,0.14])[0]
    if f=="sqli": return random.choices(SQLI_VARIANTS,[0.25,0.25,0.2,0.2,0.1])[0]
    if f=="redirect": return random.choices(REDIR_VARIANTS,[0.45,0.25,0.15,0.15])[0]
    return "none"

def choose_loc():
    return random.choices(["query","form","json"], [0.45,0.4,0.15])[0]

def choose_method(loc):
    if loc=="query": return random.choices(["GET","POST"], [0.8,0.2])[0]
    if loc=="form":  return random.choices(["POST","PUT"], [0.9,0.1])[0]
    return random.choices(["POST","PUT","PATCH"], [0.8,0.15,0.05])[0]

def content_type_for(loc):
    if loc=="json": return "application/json"
    if loc=="form": return "application/x-www-form-urlencoded"
    return "text/html"

def gen_endpoint_and_param(family):
    loc = choose_loc()
    meth = choose_method(loc)
    dom  = rand_domain()
    depth = random.randint(1,3)
    path = rand_path(depth)
    pname = random.choice(POOL[family] + random.sample(POOL["neutral"], k=random.randint(0,2)))
    q=f=j=[]
    if loc=="query": q=[pname]; f=[]; j=[]
    elif loc=="form": f=[pname]; q=[]; j=[]
    else: j=[pname]; q=[]; f=[]
    skey = shape_key(meth, path, q, f, j)
    url = f"https://{dom}{path}" + (("?"+pname+"=") if loc=="query" else "")
    return {
        "endpoint": {"method":meth, "url":url, "shape_key":skey, "path_depth": depth, "domain": dom},
        "param": {"name": pname, "loc": loc, "content_type": content_type_for(loc)},
    }

def build_features(ep, param, family, hidden_variant):
    pname = param["name"]; tokens = tokenize_param_name(pname)
    loc = param["loc"]; ct = param["content_type"]; depth = ep["path_depth"]; dom = ep["domain"]
    hints = {
        "name_hint_search": int(any(t in ("q","query","search","s","term") for t in tokens)),
        "name_hint_id": int(any(t in ("id","uid","user","pid","product","order","ref","idx","num") for t in tokens)),
        "name_hint_redirect": int(any(t in ("next","return","redirect","url","target","dest","goto","continue","callback","cb") for t in tokens)),
    }
    prev = {"prev_reflect_raw":0,"prev_reflect_html":0,"prev_reflect_attr":0,"prev_len_delta":0,"prev_status_delta":0,"prev_sql_error":0,"prev_redirect_signal":0}
    if family=="xss":
        if hidden_variant=="raw": prev["prev_reflect_raw"]=1
        elif hidden_variant=="attr": prev["prev_reflect_attr"]=1
        elif hidden_variant in ("js","html_reflect"): prev["prev_reflect_html"]=1
        prev["prev_len_delta"] = random.choice([48,96,128,192]) if any(prev.values()) else random.choice([0,8,16,24])
    elif family=="sqli":
        if hidden_variant=="error": prev["prev_sql_error"]=1
        elif hidden_variant=="time": prev["prev_len_delta"]=random.choice([0,8,16])
        elif hidden_variant=="boolean": prev["prev_len_delta"]=random.choice([24,40,56])
    elif family=="redirect":
        if hidden_variant in ("open_external","same_host"):
            prev["prev_redirect_signal"]=1
            prev["prev_status_delta"]=random.choice([0,302,301])
            prev["prev_len_delta"]=random.choice([20,40,60])
    feats = {
        "param_name_tokens": tokens,
        "loc_query": int(loc=="query"), "loc_form": int(loc=="form"), "loc_json": int(loc=="json"),
        "ct_json": int(ct=="application/json"), "ct_form": int(ct=="application/x-www-form-urlencoded"),
        "url_path_depth": depth, "domain_tokens": domain_tokens(dom),
    }
    feats.update(hints); feats.update(prev); return feats

def label_xss(pid, v):
    strong, weak = set(), set()
    if v=="raw":
        strong |= {"xss.oneliner.img_onerror","xss.oneliner.svg_onload","xss.oneliner.body_onload","xss.polyglot.svg_data"}
        weak   |= {"xss.html.tag_echo","xss.template.mustache","xss.attr.breakout.quote","xss.attr.breakout.space"}
    elif v=="attr":
        strong |= {"xss.attr.breakout.quote","xss.attr.breakout.space","xss.attr.href_jsurl"}
        weak   |= {"xss.oneliner.img_onerror","xss.html.tag_echo","xss.polyglot.svg_data"}
    elif v=="js":
        strong |= {"xss.dom.script_injection","xss.dom.event_handler","xss.js.url_javascript"}
        weak   |= {"xss.oneliner.img_onerror","xss.attr.breakout.quote","xss.html.tag_echo"}
    elif v=="html_reflect":
        weak   |= set(XSS_PAYLOADS)  # reflects but sanitized
    return 2 if pid in strong else 1 if pid in weak else 0

def label_sqli(pid, v):
    strong, weak = set(), set()
    if v=="union":
        strong |= {"sqli.union.null","sqli.union.select_1"}; weak |= {"sqli.stack_comment","sqli.inline_comment","sqli.numeric_or1eq1"}
    elif v=="boolean":
        strong |= {"sqli.boolean_true","sqli.boolean_false","sqli.numeric_or1eq1"}; weak |= {"sqli.union.null","sqli.inline_comment","sqli.like_wildcards"}
    elif v=="time":
        strong |= {"sqli.time.sleep5","sqli.time.benchmark"}; weak |= {"sqli.union.null","sqli.like_wildcards"}
    elif v=="error":
        strong |= {"sqli.error.oracle","sqli.error.mysql"}; weak |= {"sqli.union.select_1","sqli.stack_comment"}
    return 2 if pid in strong else 1 if pid in weak else 0

def label_redir(pid, v):
    strong, weak = set(), set()
    if v=="open_external":
        strong |= {"redir.http.full","redir.https.full","redir.protocol_relative","redir.double_urlencode","redir.path_scheme_encoded"}
        weak   |= {"redir.base64_url","redir.js_location","redir.open_redirect_param"}
    elif v=="same_host":
        weak   |= {"redir.http.full","redir.https.full","redir.protocol_relative","redir.open_redirect_param"}
    return 2 if pid in strong else 1 if pid in weak else 0

def gen_group(family: str, n_candidates: int):
    variant = pick_variant(family)
    ep = gen_endpoint_and_param(family)
    feats = build_features(ep["endpoint"], ep["param"], family, variant)
    payloads = {"xss": XSS_PAYLOADS, "sqli": SQLI_PAYLOADS, "redirect": REDIR_PAYLOADS}[family]
    cands = random.sample(payloads, k=min(n_candidates, len(payloads)))
    for pid in cands:
        if family=="xss": lab = label_xss(pid, variant)
        elif family=="sqli": lab = label_sqli(pid, variant)
        else: lab = label_redir(pid, variant)
        yield {
            "endpoint": {k: ep["endpoint"][k] for k in ("method","url","shape_key")},
            "param":    {k: ep["param"][k]    for k in ("name","loc","content_type")},
            "family": family,
            "payload_id": pid,
            "features": feats,
            "label": lab,
            "score_components": {}
        }

def write_split(out_dir: Path, split: str, groups_per_family: int, cands_per_group: int):
    p = out_dir / f"synth_{split}.jsonl"
    with p.open("w", encoding="utf-8") as f:
        for fam in ("xss","sqli","redirect"):
            for _ in range(groups_per_family):
                for row in gen_group(fam, cands_per_group):
                    f.write(json.dumps(row, ensure_ascii=False) + "\n")
    return p

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="data/ml/synth", help="output dir")
    ap.add_argument("--groups", type=int, default=300, help="groups per family (train)")
    ap.add_argument("--cands", type=int, default=12, help="candidates per group")
    ap.add_argument("--valid_groups", type=int, default=80)
    ap.add_argument("--test_groups", type=int, default=80)
    args = ap.parse_args()

    out = Path(args.out); out.mkdir(parents=True, exist_ok=True)
    train = write_split(out, "train", args.groups, args.cands)
    valid = write_split(out, "valid", args.valid_groups, args.cands)
    test  = write_split(out, "test",  args.test_groups,  args.cands)

    print("Wrote:", train, valid, test)

if __name__ == "__main__":
    main()
