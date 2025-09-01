# backend/modules/ml/features.py
from __future__ import annotations
from urllib.parse import urlparse

def extract_feats(endpoint: dict, param: dict, family: str, payload_id: str) -> dict:
    # Mirror generator fields (keep them stable!)
    url = endpoint.get("url","")
    dom = urlparse(url).netloc
    path = urlparse(url).path
    depth = max(1, path.count("/"))
    pname = (param.get("name") or "").replace("-", "_")
    tokens = [t for t in pname.split("_") if t][:3]
    loc = param.get("loc","query")
    ct = param.get("content_type","text/html")

    def dom_tokens(d):
        return [p for p in d.split(".") if p and p not in ("www","api")]

    hints = {
        "name_hint_search": int(any(t in ("q","query","search","s","term") for t in tokens)),
        "name_hint_id": int(any(t in ("id","uid","user","pid","product","order","ref","idx","num") for t in tokens)),
        "name_hint_redirect": int(any(t in ("next","return","redirect","url","target","dest","goto","continue","callback","cb") for t in tokens)),
    }

    feats = {
        "param_name_tokens": tokens,
        "loc_query": int(loc=="query"), "loc_form": int(loc=="form"), "loc_json": int(loc=="json"),
        "ct_json": int(ct=="application/json"), "ct_form": int(ct=="application/x-www-form-urlencoded"),
        "url_path_depth": depth,
        "domain_tokens": dom_tokens(dom),
        # NOTE: "prev_*" signals should come from your cheap pre-probe pass at runtime.
        # If you don't have them, set them to 0.
        "prev_reflect_raw": 0, "prev_reflect_html": 0, "prev_reflect_attr": 0,
        "prev_len_delta": 0, "prev_status_delta": 0,
        "prev_sql_error": 0, "prev_redirect_signal": 0,
    }
    return feats
