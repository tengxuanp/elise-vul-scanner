from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeoutError
from urllib.parse import urlparse, urlencode
from bs4 import BeautifulSoup
from html import escape

class FeatureExtractor:
    def extract_features(self, url, param, payload, method="GET"):
        parsed = urlparse(url)
        if parsed.hostname not in ["localhost", "127.0.0.1"]:
            print(f"[✘] Blocked external domain: {parsed.hostname}")
            return None

        html = ""
        executed_flag = {"value": False}  # ✅ mutable for closure access

        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                context = browser.new_context()
                page = context.new_page()

                # ✅ JS Execution Detection (alert, confirm, prompt)
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
                    print(f"[✘] Timeout: {url}")
                    return None
                except Exception as e:
                    print(f"[✘] Navigation error: {e}")
                    return None
                finally:
                    browser.close()
        except Exception as e:
            print(f"[✘] Playwright setup error: {e}")
            return None

        # === Reflection Detection ===
        encoded_payload = escape(payload)
        reflection_type = None
        if payload in html:
            reflection_type = "raw"
        elif encoded_payload in html:
            reflection_type = "encoded"
        elif payload[:6] in html or payload[-6:] in html:
            reflection_type = "partial"
        else:
            return None  # No reflection

        # === Context Classification ===
        soup = BeautifulSoup(html, "html.parser")
        tag_feature = 0
        attr_feature = 0
        quote_feature = 0
        reflection_context = "html"

        for tag in soup.find_all():
            tag_str = str(tag)

            if payload in tag_str or encoded_payload in tag_str:
                tag_feature = hash(tag.name) % 10

                # Check for JS context
                if tag.name == "script":
                    reflection_context = "js"

                # Check for attribute injection
                for attr in tag.attrs:
                    attr_val = tag.attrs[attr]
                    if isinstance(attr_val, list):
                        attr_val = " ".join(attr_val)
                    if payload in attr_val or encoded_payload in attr_val:
                        attr_feature = hash(attr) % 10
                        quote_feature = 1 if '"' in attr_val else 2
                        reflection_context = "attribute"

        # === Flags for ML Vector ===
        type_flag = {"raw": 1, "encoded": 2, "partial": 3}.get(reflection_type, 0)
        context_flag = {"html": 1, "attribute": 2, "js": 3}.get(reflection_context, 0)
        execution_flag = 1 if executed_flag["value"] else 0

        return [
            tag_feature,        # 0: hash(tag)
            attr_feature,       # 1: hash(attr)
            0,                  # 2: reserved
            0,                  # 3: reserved
            quote_feature,      # 4: 0/1/2
            type_flag,          # 5: reflection type
            context_flag,       # 6: reflection context
            execution_flag,     # 7: was alert() triggered
        ] + [0] * 9  # Pad to 17-D
