import random

CANARY = "EliseXSSCanary123"

EVENT_ATTRS = ["onclick","onmouseover","onfocus","onload","onerror","oninput","onchange"]
SAFE_ATTRS  = ["title","value","placeholder","data-name","aria-label"]
URL_ATTRS   = ["href","src","action","formaction"]

HTML_WRAPPERS = [
    '<div class="card"><h1>Profile</h1><p>Hello, {MARK}</p></div>',
    '<p>Message: {MARK}</p>',
    '<ul><li>{MARK}</li><li>static</li></ul>',
    '<div id="msg">{MARK}</div>',
]

ATTR_WRAPPERS = [
    '<input type="text" {attr}="{MARK}">',
    '<span {attr}="{MARK}">x</span>',
    '<a {attr}="https://example.com/?q={MARK}">link</a>',
    '<div data-x="{MARK}"></div>',
]

JS_STRING_WRAPPERS = [
    '<script>var msg="{MARK}"; document.body.innerHTML=msg;</script>',
    '<script>console.log("audit", "{MARK}");</script>',
    '<script>let x = "{MARK}".trim();</script>',
    '<script>document.getElementById("x").dataset.n="{MARK}";</script>',
]

URL_WRAPPERS = [
    '<a href="/search?q={MARK}">search</a>',
    '<img src="/img?name={MARK}">',
    '<form action="/submit?redir={MARK}" method="post"></form>',
]

CSS_WRAPPERS = [
    '<style>.user::after{content:"{MARK}";}</style>',
    '<div style="background:url(/img?u={MARK})"></div>',
    '<div style="--user:{MARK}"></div>',
]

COMMENT_WRAPPERS = [
    '<!-- {MARK} --><div>ok</div>',
    '<div><!--note:{MARK}--></div>',
]

JSON_WRAPPERS = [
    '<script type="application/json">{"msg":"{MARK}","ok":true}</script>',
    '<script id="boot" type="application/json">{"u":"{MARK}","i":1}</script>',
]

def pick_template(ctx: str) -> str:
    bank = {
        "html_body": HTML_WRAPPERS,
        "attr": ATTR_WRAPPERS,
        "js_string": JS_STRING_WRAPPERS,
        "url": URL_WRAPPERS,
        "css": CSS_WRAPPERS,
        "comment": COMMENT_WRAPPERS,
        "json": JSON_WRAPPERS,
    }[ctx]
    t = random.choice(bank)
    if ctx == "attr":
        # randomize attribute kind
        pool = SAFE_ATTRS + URL_ATTRS
        t = t.replace("{attr}", random.choice(pool))
    return t
