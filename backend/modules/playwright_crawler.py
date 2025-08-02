from playwright.sync_api import sync_playwright
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs

STATIC_EXTENSIONS = (
    ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg",
    ".ico", ".woff", ".woff2", ".ttf", ".map", ".json", ".txt"
)

def is_static_resource(url):
    return url.lower().endswith(STATIC_EXTENSIONS)

def crawl_site(target_url, max_depth=2):
    visited = set()
    raw_endpoints = []
    captured_requests = []

    def normalize_url(url):
        parsed = urlparse(url)
        params = sorted(parse_qs(parsed.query).keys())
        return parsed.path, tuple(params)

    def deduplicate(endpoints):
        seen = set()
        unique = []
        for ep in endpoints:
            key = (ep.get("url"), ep.get("method"), tuple(sorted(ep.get("params", []))))
            if key not in seen and ep.get("url"):
                seen.add(key)
                unique.append(ep)
        return unique

    def crawl(url, depth, browser):
        if depth > max_depth or normalize_url(url) in visited:
            return
        visited.add(normalize_url(url))
        page = browser.new_page()

        def capture_request(request):
            if not is_static_resource(request.url):
                captured_requests.append({
                    "method": request.method,
                    "url": request.url,
                    "headers": request.headers,
                    "post_data": request.post_data
                })

        page.on("request", capture_request)

        try:
            page.goto(url, timeout=15000, wait_until="networkidle")
            soup = BeautifulSoup(page.content(), "html.parser")

            # Capture form actions
            for form in soup.find_all("form"):
                action = form.get("action") or url
                method = form.get("method", "GET").upper()
                full_action_url = urljoin(url, action)
                if not is_static_resource(full_action_url):
                    form_params = [i.get("name") for i in form.find_all("input") if i.get("name")]
                    raw_endpoints.append({
                        "url": full_action_url,
                        "method": method,
                        "params": form_params or []
                    })

            # Capture <a href> links and click them
            for link in soup.find_all("a", href=True):
                href = link["href"]
                full_url = urljoin(url, href)
                if href.startswith("#/"):
                    # Manually trigger client-side route rendering
                    try:
                        page.goto(full_url, timeout=15000, wait_until="networkidle")
                        sub_soup = BeautifulSoup(page.content(), "html.parser")
                        # Try to identify queryable input params
                        inputs = sub_soup.find_all("input")
                        param_names = [inp.get("name") for inp in inputs if inp.get("name")]
                        raw_endpoints.append({
                            "url": full_url,
                            "method": "GET",
                            "params": param_names or []
                        })
                    except Exception as e:
                        print(f"[WARN] Could not load client-side route {full_url}: {e}")
                elif urlparse(full_url).netloc == urlparse(target_url).netloc and not is_static_resource(full_url):
                    get_params = list(parse_qs(urlparse(full_url).query).keys())
                    raw_endpoints.append({
                        "url": full_url,
                        "method": "GET",
                        "params": get_params or []
                    })
                    crawl(full_url, depth + 1, browser)

        except Exception as e:
            print(f"[ERROR] Failed to crawl {url}: {e}")
        finally:
            page.close()

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        crawl(target_url, 0, browser)
        browser.close()

    return deduplicate(raw_endpoints), deduplicate(captured_requests)
