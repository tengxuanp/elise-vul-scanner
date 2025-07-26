from mitmproxy import http
import json
import os

endpoints = []

def request(flow: http.HTTPFlow) -> None:
    req = flow.request

    try:
        with open("./data/target_domains.json") as f:
            target_domains = json.load(f)
    except:
        target_domains = []

    print(f"[MITMPROXY] Intercepted: {req.method} {req.pretty_host}{req.path}")
    print(f"[MITMPROXY] Intercepted request: {flow.request.method} {flow.request.pretty_url}")

    if req.method in ["GET", "POST"]:
        if any(domain.lower() in req.pretty_host.lower() for domain in target_domains):
            params = list(req.query.keys())
            body_params = []
            try:
                body = json.loads(req.content)
                if isinstance(body, dict):
                    body_params = list(body.keys())
            except:
                pass
            endpoints.append({
                "url": req.pretty_url.split("?")[0],
                "method": req.method,
                "params": params + body_params
            })
            print(f"[MITMPROXY] Captured: {req.method} {req.pretty_url}")

def done():
    os.makedirs("./data", exist_ok=True)
    with open("./data/proxy_captured_endpoints.json", "w") as f:
        json.dump(endpoints, f, indent=2)
    print(f"[MITMPROXY] Written {len(endpoints)} endpoints.")
