#!/usr/bin/env python3
# Copyright (c) 2026. TxnLab Inc.
# SPDX-License-Identifier: Apache-2.0
"""Generate tokenize_corpus.json — ground-truth token counts for the reserve
input-token bound.

The bound in proto/go/tokenize + proto/ts/src/tokenize is a model-agnostic UPPER
bound: it must never come in below what a real tokenizer would charge, because
the node ceilings billing at the reserved max_price and the operator absorbs any
shortfall. Hand-picked vectors can pin the bound's *output*, but they can't
establish that safety property. This script does: it renders each corpus sample
the way a serving stack actually would, tokenizes it with real BPE vocabularies,
and records the worst (largest) count. The Go and TS corpus tests then assert
bound(sample) >= real_tokens for every sample.

Run manually after changing the corpus or the bound's constants — the output is
checked in, so neither test suite needs Python or a tokenizer at test time:

    python3 -m venv .venv && .venv/bin/pip install tiktoken pillow
    .venv/bin/python proto/testdata/gen_tokenize_corpus.py

Ground truth is deliberately conservative in the bound's favour being *tested*,
not in the bound's favour being *granted*: where a modelling choice is arguable
(chat-template overhead, how tool schemas are injected) we pick the variant that
produces MORE real tokens, so a bound that passes here has real margin.
"""

from __future__ import annotations

import base64
import io
import json
import math
import pathlib
import sys

try:
    import tiktoken
except ImportError:  # pragma: no cover - operator-facing message
    sys.exit("tiktoken is required: pip install tiktoken")

try:
    from PIL import Image
except ImportError:  # pragma: no cover - operator-facing message
    sys.exit("pillow is required (image dimensions): pip install pillow")

HERE = pathlib.Path(__file__).resolve().parent
CORPUS_DIR = HERE / "tokenize_corpus"
OUT_PATH = HERE / "tokenize_corpus.json"

# Vocabularies to measure against. o200k_base (GPT-4o/5 family) and cl100k_base
# (GPT-4/3.5, and the closest widely-available stand-in for the older
# open-weight vocabularies) bracket the range we care about: cl100k is markedly
# worse on CJK and emoji, which is exactly where a bytes-per-token floor is at
# risk of UNDER-counting.
TOKENIZERS = ("o200k_base", "cl100k_base")

# Per-message chat-template overhead. A ChatML-style template emits role and
# turn delimiters around every message (<|im_start|>role\n ... <|im_end|>\n).
# Four tokens per message is the long-standing OpenAI accounting for this, plus
# three for the trailing assistant priming.
TOKENS_PER_MESSAGE = 4
TOKENS_PER_REPLY_PRIMER = 3

# OpenAI vision tile math — the reference the bound's image term implements.
IMAGE_TOKENS_LOW = 85
IMAGE_TOKENS_HIGH_BASE = 85
IMAGE_TOKENS_HIGH_TILE = 170
IMAGE_TILE_EDGE_PX = 512
# Fallback when the true dimensions are genuinely unknowable from the body (a
# remote https:// URL, or bytes that don't parse). The bound uses the same
# fallback, so ground truth has to as well or the comparison is meaningless.
IMAGE_DEFAULT_WIDTH_PX = 2048
IMAGE_DEFAULT_HEIGHT_PX = 2048


def image_tokens(width: int, height: int, detail: str) -> int:
    if detail == "low":
        return IMAGE_TOKENS_LOW
    tiles_x = max(1, math.ceil(width / IMAGE_TILE_EDGE_PX))
    tiles_y = max(1, math.ceil(height / IMAGE_TILE_EDGE_PX))
    return IMAGE_TOKENS_HIGH_BASE + IMAGE_TOKENS_HIGH_TILE * tiles_x * tiles_y


def decode_dimensions(url: str) -> tuple[int, int] | None:
    """True pixel dimensions of a data: URL, or None when unknowable.

    Uses a full decoder (Pillow) on purpose: this is the reference the bound's
    hand-rolled, header-only parser is checked against. The bound may NOT decode
    — it runs on untrusted payer input inside the node — but ground truth can.
    """
    if not url.startswith("data:"):
        return None
    _, _, payload = url.partition(",")
    try:
        raw = base64.b64decode(payload, validate=False)
        with Image.open(io.BytesIO(raw)) as im:
            return im.width, im.height
    except Exception:
        return None


def part_text(part: dict) -> str:
    """Text a content part contributes to the rendered prompt."""
    for key in ("text", "input_text", "output_text"):
        v = part.get(key)
        if isinstance(v, str):
            return v
    return ""


def is_image_part(part: dict) -> bool:
    return str(part.get("type", "")).lower() in ("image_url", "input_image")


def image_url_of(part: dict) -> str:
    v = part.get("image_url")
    if isinstance(v, str):
        return v
    if isinstance(v, dict) and isinstance(v.get("url"), str):
        return v["url"]
    return ""


def image_detail_of(part: dict) -> str:
    detail = part.get("detail")
    nested = part.get("image_url")
    if isinstance(nested, dict) and isinstance(nested.get("detail"), str):
        detail = nested["detail"]
    detail = str(detail or "").lower()
    # "auto" resolves to high for anything but a thumbnail — the conservative
    # reading, and what the bound assumes.
    return "low" if detail == "low" else "high"


def render(body: dict) -> tuple[str, int, int]:
    """Render a request body to (prompt_text, message_count, image_tokens).

    Models the serving side: the JSON envelope disappears, message contents and
    tool schemas become prompt text, and images are priced by tile math rather
    than by the length of their data URL.
    """
    chunks: list[str] = []
    messages = 0
    img_tokens = 0

    if isinstance(body.get("instructions"), str):
        chunks.append(body["instructions"])
        messages += 1

    # Tool schemas are injected into the prompt close to verbatim by every
    # template that supports them, so they are charged as rendered JSON text.
    tools = body.get("tools")
    if isinstance(tools, list) and tools:
        for entry in tools:
            chunks.append(json.dumps(entry, ensure_ascii=False, separators=(",", ":")))
        messages += 1
    if isinstance(body.get("tool_choice"), str):
        chunks.append(body["tool_choice"])

    for key in ("messages", "input"):
        items = body.get(key)
        if not isinstance(items, list):
            continue
        for msg in items:
            if not isinstance(msg, dict):
                continue
            messages += 1
            if isinstance(msg.get("role"), str):
                chunks.append(msg["role"])
            content = msg.get("content")
            if isinstance(content, str):
                chunks.append(content)
            elif isinstance(content, list):
                for part in content:
                    if not isinstance(part, dict):
                        continue
                    if is_image_part(part):
                        detail = image_detail_of(part)
                        dims = decode_dimensions(image_url_of(part))
                        w, h = dims or (IMAGE_DEFAULT_WIDTH_PX, IMAGE_DEFAULT_HEIGHT_PX)
                        img_tokens += image_tokens(w, h, detail)
                    else:
                        chunks.append(part_text(part))

    return "\n".join(c for c in chunks if c), messages, img_tokens


def main() -> None:
    encodings = {name: tiktoken.get_encoding(name) for name in TOKENIZERS}
    samples = []

    for path in sorted(CORPUS_DIR.glob("*.json")):
        raw = path.read_bytes()
        body = json.loads(raw)
        prompt, messages, img_tokens = render(body)

        per_tokenizer = {}
        for name, enc in encodings.items():
            text_tokens = len(enc.encode(prompt, disallowed_special=()))
            overhead = messages * TOKENS_PER_MESSAGE + TOKENS_PER_REPLY_PRIMER
            per_tokenizer[name] = text_tokens + overhead + img_tokens

        samples.append(
            {
                "name": path.stem,
                "body_bytes": len(raw),
                "messages": messages,
                "image_tokens": img_tokens,
                "tokens": per_tokenizer,
                # The number the bound must meet or exceed.
                "real_tokens": max(per_tokenizer.values()),
            }
        )

    out = {
        "version": 1,
        "comment": (
            "Ground-truth token counts for proto/testdata/tokenize_corpus/*.json, measured with "
            "real BPE vocabularies. real_tokens is the WORST (largest) count across tokenizers — "
            "the reserve input-token bound must be >= it for every sample. "
            "Regenerate via: python3 proto/testdata/gen_tokenize_corpus.py (needs tiktoken + pillow). "
            "Consumed by proto/go/tokenize/corpus_test.go and proto/ts/test/tokenize-corpus.test.ts."
        ),
        "tokenizers": list(TOKENIZERS),
        "tokens_per_message": TOKENS_PER_MESSAGE,
        "tokens_per_reply_primer": TOKENS_PER_REPLY_PRIMER,
        "samples": samples,
    }
    OUT_PATH.write_text(json.dumps(out, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    print(f"wrote {OUT_PATH} ({len(samples)} samples)")
    for s in samples:
        print(f"  {s['name']:<26} {s['body_bytes']:>7}B  real={s['real_tokens']:>6}")


if __name__ == "__main__":
    main()
