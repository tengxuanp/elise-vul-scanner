from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeoutError
from urllib.parse import urlparse, urlencode
from bs4 import BeautifulSoup
from html import escape
import logging

class FeatureExtractor:
    def extract_features(self, url, param, payload, method="GET"):
        # === Parse Target Info ===
        parsed = urlparse(url)
        domain_feature = hash(parsed.netloc) % 10
        path_feature = hash(parsed.path) % 10

        html = ""
        executed_flag = {"value": False}  # Mutable for JS dialog hook
        reflection_type = "none"
        reflection_context = "html"
        tag_feature = attr_feature = quote_feature = 0

        # === Playwright Session ===
        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                context = browser.new_context()
                page = context.new_page()

                # Hook: JS Execution Detection
                def on_dialog(dialog):
                    executed_flag["value"] = True
                    dialog.dismiss()
                page.on("dialog", on_dialog)

                try:
                    if method.upper() == "POST":
                        base_url = url.split("?")[0]
                        page.request.post(base_url, data={param: payload})
                        page.goto(base_url, wait_until="domcontentloaded", timeout=10000)
                    else:
                        target = f"{url}?{urlencode({param: payload})}"
                        page.goto(target, wait_until="domcontentloaded", timeout=10000)

                    html = page.content()

                except PlaywrightTimeoutError:
                    logging.warning(f"[Timeout] {url}")
                except Exception as e:
                    logging.error(f"[Navigation Error] {url} — {e}")
                finally:
                    browser.close()

        except Exception as e:
            logging.error(f"[Playwright Setup Error] {e}")
            return self._default_vector(param, payload, domain_feature, path_feature)

        # === Reflection Detection ===
        if html:
            encoded_payload = escape(payload)
            if payload in html:
                reflection_type = "raw"
            elif encoded_payload in html:
                reflection_type = "encoded"
            elif payload[:6] in html or payload[-6:] in html:
                reflection_type = "partial"
            else:
                logging.warning(f"[No Reflection] {url} param='{param}'")

        else:
            logging.warning(f"[Empty HTML] Could not extract content from {url}")
            return self._default_vector(param, payload, domain_feature, path_feature)

        # === Context Classification ===
        try:
            soup = BeautifulSoup(html, "html.parser")
            for tag in soup.find_all():
                tag_str = str(tag)

                if payload in tag_str or escape(payload) in tag_str:
                    tag_feature = hash(tag.name) % 10
                    if tag.name == "script":
                        reflection_context = "js"

                    for attr in tag.attrs:
                        val = tag.attrs[attr]
                        val = " ".join(val) if isinstance(val, list) else val
                        if payload in val or escape(payload) in val:
                            attr_feature = hash(attr) % 10
                            quote_feature = 1 if '"' in val else 2
                            reflection_context = "attribute"

        except Exception as e:
            logging.warning(f"[Parsing Error] {url}: {e}")

        # === ML Feature Vector ===
        type_flag = {"raw": 1, "encoded": 2, "partial": 3, "none": 0}[reflection_type]
        context_flag = {"html": 1, "attribute": 2, "js": 3}.get(reflection_context, 0)
        execution_flag = 1 if executed_flag["value"] else 0

        return [
            tag_feature,          # 0
            attr_feature,         # 1
            domain_feature,       # 2
            path_feature,         # 3
            quote_feature,        # 4
            type_flag,            # 5
            context_flag,         # 6
            execution_flag,       # 7
            len(param) % 10,      # 8
            len(payload) % 10     # 9
        ] + [0] * 7               # 10-16

    def _default_vector(self, param, payload, domain_feature, path_feature):
        return [
            0, 0,                 # tag, attr
            domain_feature,       # domain
            path_feature,         # path
            0, 0, 0, 0,           # quote, type_flag, context, js_exec
            len(param) % 10,
            len(payload) % 10
        ] + [0] * 7
