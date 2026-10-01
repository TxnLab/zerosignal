#!/usr/bin/env python3
# Copyright (c) 2026. TxnLab Inc.
# SPDX-License-Identifier: Apache-2.0
"""Regenerate proto/testdata/tokenize_corpus/*.json — the request bodies the
input-token bound is measured against.

This exists so the corpus is not a pile of opaque committed artifacts. It is
fully self-contained and deterministic (fixed seed, no reads of repo source), so
anyone can extend the corpus or rebuild an image sample for a new format and get
byte-identical output for the unchanged ones.

Two scripts, two jobs:
  * this one produces the SAMPLES (request bodies)
  * gen_tokenize_corpus.py measures them with real tokenizers to produce
    tokenize_corpus.json (the ground truth the tests assert against)

Run both, in that order, after changing anything here:

    python3 -m venv .venv && .venv/bin/pip install tiktoken pillow
    .venv/bin/python proto/testdata/gen_tokenize_corpus_samples.py
    .venv/bin/python proto/testdata/gen_tokenize_corpus.py
    cd proto/go && go test ./tokenize -run TestVectors -update

Images are deliberately SMOOTH (gradients, not noise). They exercise exactly the
same header paths as noisy ones — the parser never looks past the header — while
compressing to a fraction of the size, which keeps the fixture reasonable.
"""

from __future__ import annotations

import base64
import io
import json
import pathlib
import random
import sys

try:
    from PIL import Image
except ImportError:  # pragma: no cover - operator-facing message
    sys.exit("pillow is required: pip install pillow")

OUT = pathlib.Path(__file__).resolve().parent / "tokenize_corpus"
OUT.mkdir(parents=True, exist_ok=True)

random.seed(20260728)


def write(name: str, body: dict) -> None:
    p = OUT / f"{name}.json"
    p.write_text(json.dumps(body, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    print(f"{name:<30} {p.stat().st_size:>8} bytes")


def chat(messages, **extra):
    body = {"model": "zs-test-model", "messages": messages, "stream": True}
    body.update(extra)
    return body


def user(content):
    return chat([{"role": "user", "content": content}])


# --------------------------------------------------------------------- text
# Natural English prose. Inlined rather than read from a source file so the
# corpus is reproducible from this script alone.
PROSE = (
    "The reserve is a realistic upper bound on the input tokens a request will "
    "consume, not a tokenizer output. It is used as the input side of the "
    "ticket's maximum price, so it must never come in below what the model is "
    "actually billed for. Overestimates only widen the refund at settlement, "
    "while an underestimate means the payer reserves too little and the operator "
    "absorbs the difference. Because the serving node re-computes the same bound "
    "over the decrypted body, the two implementations have to agree exactly. "
)

CODE = '''func InputTokenBoundV2(body []byte) uint64 {
\tbody = bytes.TrimPrefix(body, bomPrefix)
\tif len(body) == 0 {
\t\treturn FlatMargin
\t}
\turlBytes, imageTokens, ok := imageStatsV2(body)
\tif !ok {
\t\treturn saturatingAdd(ceilDivU64(uint64(len(body)), BytesPerToken), FlatMargin)
\t}
\ttextBytes := uint64(len(body))
\tif urlBytes < textBytes {
\t\ttextBytes -= urlBytes
\t}
\treturn saturatingAdd(ceilDivU64(textBytes, BytesPerToken)+imageTokens, FlatMargin)
}
'''

write("prose_short", user("hello world, this is a small question"))
write("prose_medium", user(PROSE * 3))
write(
    "prose_multiturn",
    chat(
        [{"role": "system", "content": "You are a helpful assistant. Answer concisely."}]
        + [
            {"role": r, "content": PROSE[: 300 + i * 40]}
            for i, r in enumerate(["user", "assistant"] * 5)
        ]
    ),
)
write("code_go", user("explain this:\n\n" + CODE * 4))
write("code_ts", user("review:\n\n" + (CODE.replace("\t", "  ") * 3)))

# Adversarial ASCII — the classes a bytes-per-token ratio gets wrong.
write("adversarial_base64", user(base64.b64encode(bytes(range(256)) * 12).decode()))
write("adversarial_hex", user((bytes(range(256)) * 8).hex()))
write(
    "adversarial_uuids",
    user(" ".join("%08x-%04x-%04x-%04x-%012x" % (i, i, i, i, i) for i in range(200))),
)
write(
    "adversarial_minified_js",
    user(
        (
            "function a(b,c){var d=b.length,e=[];for(var f=0;f<d;f++){e.push(b[f]*c);}"
            "return e.filter(function(g){return g>0;}).map(function(h){return h+1;});}"
        )
        * 12
    ),
)
write(
    "adversarial_rare_words",
    user(
        (
            "pneumonoultramicroscopicsilicovolcanoconiosis floccinaucinihilipilification "
            "antidisestablishmentarianism hippopotomonstrosesquippedaliophobia "
            "supercalifragilisticexpialidocious pseudopseudohypoparathyroidism "
        )
        * 10
    ),
)
write(
    "adversarial_short_rare_words",
    user(
        (
            "zylot brimp vexil quorn thrap glimn skorb pliven drask morvel "
            "yertan sploon kravix mundel fethro qualbin nyxor trebbin walgor "
        )
        * 14
    ),
)

# Non-ASCII scripts.
write("cjk_zh", user("这是一个关于人工智能的问题。" * 120))
write("cjk_ja", user("これは人工知能に関する質問です。" * 120))
write("cjk_ko", user("이것은 인공지능에 관한 질문입니다. " * 100))
write("emoji_dense", user("🙂🎉🚀🧠💡🔥✨🌍🐙🦀" * 100))
write("mixed_cjk_latin", user("The 中文 model 处理 mixed 输入 correctly. " * 100))
write("cyrillic_greek", user("Привет мир καλημέρα κόσμε " * 150))
write(
    "latin_polish",
    user("Zażółć gęślą jaźń. Wszystkie języki naturalne mają swoje osobliwości. " * 12),
)
write(
    "latin_turkish",
    user("Çalışmalarımızın büyük çoğunluğu kullanıcıların gereksinimlerini karşılar. " * 12),
)
write(
    "latin_vietnamese",
    user("Chúng tôi đang xây dựng một hệ thống phân tán để xử lý các yêu cầu. " * 12),
)


def tool(n: int) -> dict:
    return {
        "type": "function",
        "function": {
            "name": f"lookup_record_{n}",
            "description": f"Look up record {n} in the datastore and return its fields.",
            "parameters": {
                "type": "object",
                "properties": {
                    "record_id": {"type": "string", "description": "The record identifier."},
                    "include_deleted": {"type": "boolean", "description": "Include tombstones."},
                    "fields": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Subset of fields to return.",
                    },
                },
                "required": ["record_id"],
            },
        },
    }


write(
    "tools_many",
    chat([{"role": "user", "content": "find record 42"}], tools=[tool(i) for i in range(20)],
         tool_choice="auto"),
)
write(
    "tools_builtin",
    chat([{"role": "user", "content": "what happened in the news today?"}],
         tools=[{"type": "zs_web_search"}, {"type": "zs_web_read"}]),
)

agent_messages = [{"role": "system", "content": "You are a coding agent with filesystem access."}]
for i in range(4):
    agent_messages.append({"role": "user", "content": f"Fix the failing test in module {i}."})
    agent_messages.append(
        {
            "role": "assistant",
            "content": None,
            "tool_calls": [
                {
                    "id": f"call_{i}",
                    "type": "function",
                    "function": {
                        "name": "read_file",
                        "arguments": json.dumps({"path": f"src/module_{i}/handler.ts", "end": 120}),
                    },
                }
            ],
        }
    )
    agent_messages.append({"role": "tool", "tool_call_id": f"call_{i}", "content": CODE})
write("agent_tool_history", chat(agent_messages, tools=[tool(i) for i in range(8)]))

# ------------------------------------------------------------------- images
def render(w: int, h: int) -> Image.Image:
    """A smooth gradient. Compresses well; the parser only reads the header."""
    im = Image.new("RGB", (w, h))
    px = im.load()
    for y in range(h):
        row = (y * 255) // max(1, h - 1) if h > 1 else 0
        for x in range(w):
            px[x, y] = ((x * 255) // max(1, w - 1) if w > 1 else 0, row, 128)
    return im


def encode(w: int, h: int, fmt: str, **kw) -> bytes:
    buf = io.BytesIO()
    render(w, h).save(buf, format=fmt, **kw)
    return buf.getvalue()


def data_url(mime: str, raw: bytes) -> str:
    return f"data:{mime};base64," + base64.b64encode(raw).decode()


def image_body(url: str, detail: str = "auto"):
    return chat(
        [
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": "describe this image in detail"},
                    {"type": "image_url", "image_url": {"url": url, "detail": detail}},
                ],
            }
        ]
    )


write("image_png_512", image_body(data_url("image/png", encode(512, 512, "PNG"))))
write("image_png_1024x768", image_body(data_url("image/png", encode(1024, 768, "PNG"))))
# Larger than the 2048x2048 fallback: the case v1 UNDER-charges and v2 fixes.
write("image_png_4096", image_body(data_url("image/png", encode(4096, 4096, "PNG"))))
write("image_jpeg_800x600", image_body(data_url("image/jpeg", encode(800, 600, "JPEG", quality=50))))
# A large EXIF block pushes the SOF marker well past the first KB — the case a
# naive "read the first N bytes" parser gets wrong.
write(
    "image_jpeg_big_exif",
    image_body(
        data_url(
            "image/jpeg",
            encode(640, 480, "JPEG", quality=50, exif=b"Exif\x00\x00" + b"\x00" * 40000),
        )
    ),
)
# GIF is no longer trusted (its Logical Screen Descriptor is not the decoded
# size), so this sample exists to pin that it falls back rather than being read.
write("image_gif_320x240", image_body(data_url("image/gif", encode(320, 240, "GIF"))))
write("image_webp_vp8x", image_body(data_url("image/webp", encode(1600, 1200, "WEBP", quality=50, exact=True))))
write("image_webp_vp8", image_body(data_url("image/webp", encode(900, 700, "WEBP", quality=40))))
write("image_webp_vp8l", image_body(data_url("image/webp", encode(1280, 720, "WEBP", lossless=True))))
write("image_remote_url", image_body("https://example.com/photo.png"))
write(
    "image_truncated_png",
    image_body("data:image/png;base64," + base64.b64encode(encode(512, 512, "PNG")[:8]).decode()),
)
write("image_garbage_dataurl", image_body("data:image/png;base64,bm90LWFuLWltYWdl"))
write("image_low_detail", image_body(data_url("image/png", encode(2048, 2048, "PNG")), detail="low"))
write(
    "image_two_plus_text",
    chat(
        [
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": PROSE[:400]},
                    {"type": "image_url", "image_url": {"url": data_url("image/png", encode(512, 512, "PNG"))}},
                    {"type": "image_url", "image_url": {"url": data_url("image/png", encode(256, 256, "PNG"))}},
                ],
            }
        ]
    ),
)

# ------------------------------------------------------- shapes and edge cases
write(
    "responses_input",
    {
        "model": "zs-test-model",
        "instructions": "You are terse.",
        "input": [
            {"role": "user", "content": [{"type": "input_text", "text": PROSE[:800]}]},
            {"role": "assistant", "content": [{"type": "output_text", "text": PROSE[800:1400]}]},
        ],
        "stream": True,
    },
)
write("empty_messages", chat([]))
write("whitespace_heavy", user("\n".join("    " * 8 + f"indented line {i}" for i in range(150))))
write("json_in_content", user(json.dumps({"a": list(range(200)), "b": {"c": "d" * 200}})))

print(f"\n{len(list(OUT.glob('*.json')))} samples in {OUT}")
