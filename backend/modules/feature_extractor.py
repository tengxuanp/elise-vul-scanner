from playwright.sync_api import sync_playwright
from bs4 import BeautifulSoup

class FeatureExtractor:
    def extract_features(self, url, param, payload):
        target = f"{url}?{param}={payload}"

        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()
            page.goto(target, wait_until="networkidle")

            html = page.content()
            browser.close()

        if payload not in html:
            return None  # Not reflected

        soup = BeautifulSoup(html, "html.parser")
        tag_feature = 0
        attr_feature = 0
        quote_feature = 0

        for tag in soup.find_all():
            if payload in str(tag):
                tag_feature = hash(tag.name) % 10
                for attr in tag.attrs:
                    if payload in tag.attrs[attr]:
                        attr_feature = hash(attr) % 10
                        quote_feature = 1 if '"' in tag.attrs[attr] else 2

        return [tag_feature, attr_feature, 0, 0, quote_feature] + [0] * 12  # Dummy-padded
