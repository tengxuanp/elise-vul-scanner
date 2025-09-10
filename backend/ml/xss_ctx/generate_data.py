from __future__ import annotations
import os, json, random
from dataclasses import dataclass, asdict
from typing import List
from .templates import pick_template, CANARY
from .utils import escape

CTX_LABELS = ["html_body","attr","js_string","url","css","comment","json"]
ESC_LABELS = ["raw","html","url","js"]

@dataclass
class Sample:
    text: str
    ctx: str
    esc: str

def synth_one(ctx: str, esc: str) -> Sample:
    payload = CANARY
    # attacker-ish flavors by context
    if ctx == "attr" and random.random() < 0.35:
        payload = f'" onmouseover="alert(1)" {CANARY}'
    elif ctx == "js_string" and random.random() < 0.5:
        payload = f'{CANARY}";alert(1);//'
    elif ctx == "url" and random.random() < 0.5:
        payload = f'javascript:alert(1)#{CANARY}'
    elif ctx == "css" and random.random() < 0.4:
        payload = f'url(javascript:alert(1))/*{CANARY}*/'

    mark = escape(payload, esc)
    doc = pick_template(ctx).replace("{MARK}", mark)

    # background noise
    if random.random() < 0.4:
        doc = '<meta charset="utf-8">\n' + doc
    if random.random() < 0.3:
        doc += '\n<script>/* bootstrap */</script>'

    # partial encoding (server bugs)
    if esc in ("html","url") and random.random() < 0.15:
        half = escape(CANARY[: len(CANARY)//2], esc) + CANARY[len(CANARY)//2:]
        doc = doc.replace(mark, half)

    return Sample(text=doc, ctx=ctx, esc=esc)

def generate(n:int=50000, seed:int=7) -> List[Sample]:
    random.seed(seed)
    samples: List[Sample] = []
    for _ in range(n):
        ctx = random.choice(CTX_LABELS)
        esc = random.choices(ESC_LABELS, weights=[0.6,0.25,0.1,0.05])[0]
        samples.append(synth_one(ctx, esc))
    return samples

def dump_jsonl(path:str, samples:List[Sample]):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        for s in samples:
            f.write(json.dumps(asdict(s), ensure_ascii=False) + "\n")

if __name__ == "__main__":
    out_dir = os.environ.get("OUT_DIR","data/xss_ctx")
    os.makedirs(out_dir, exist_ok=True)
    S = generate()
    dump_jsonl(os.path.join(out_dir,"train.jsonl"), S)
    print(f"wrote {len(S)} samples → {out_dir}/train.jsonl")
