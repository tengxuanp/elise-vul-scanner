from playwright.sync_api import sync_playwright
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs


def crawl_site(target_url, max_depth=2):
    visited = set()
    raw_endpoints = []

    def normalize_url(url):
        """Normalize URL to path + sorted params tuple (for deduplication)"""
        parsed = urlparse(url)
        params = sorted(parse_qs(parsed.query).keys())
        return parsed.path, tuple(params)

    def crawl(url, depth):
        if depth > max_depth:
            return

        normalized = normalize_url(url)
        if normalized in visited:
            return
        visited.add(normalized)

        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                page = browser.new_page()
                page.goto(url, timeout=100000, wait_until="domcontentloaded")
                content = page.content()
                browser.close()

            soup = BeautifulSoup(content, 'html.parser')

            # Extract forms
            for form in soup.find_all('form'):
                action = form.get('action') or url
                method = form.get('method', 'GET').upper()
                full_action_url = urljoin(url, action)
                form_params = [i.get('name') for i in form.find_all('input') if i.get('name')]

                raw_endpoints.append({
                    "url": full_action_url,
                    "method": method,
                    "params": form_params
                })


            # Extract links and crawl them recursively
            for link in soup.find_all('a', href=True):
                href = link['href']
                full_url = urljoin(url, href)
                parsed_href = urlparse(full_url)

                if parsed_href.netloc == urlparse(target_url).netloc:
                    get_params = list(parse_qs(parsed_href.query).keys())

                    raw_endpoints.append({
                        "url": full_url,
                        "method": "GET",
                        "params": get_params
                    })

                    crawl(full_url, depth + 1)

        except Exception as e:
            print(f"[ERROR] Failed to crawl {url}: {e}")

    def deduplicate(endpoints):
        seen = set()
        unique = []
        for ep in endpoints:
            key = (ep["url"], ep["method"], tuple(sorted(ep["params"])))
            if key not in seen:
                seen.add(key)
                unique.append(ep)
        return unique

    crawl(target_url, 0)
    return deduplicate(raw_endpoints)
