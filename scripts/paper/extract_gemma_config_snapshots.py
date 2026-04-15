#!/usr/bin/env python3
"""Capture appendix-only Gemma mirror config fields into repo-local extracted snapshots."""

from __future__ import annotations

import hashlib
import json
import socket
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUTDIR = ROOT / "docs" / "paper" / "evidence" / "gemma-config-snapshots"
OUTDIR.mkdir(parents=True, exist_ok=True)

SOURCES = [
    {
        "label": "gemma_3_270m",
        "url": "https://huggingface.co/HedronCreeper/gemma-3-270m-custom-hedron/raw/ac458437b3053e9d1ef5ca71fed58f3bf84b513c/config.json",
        "fields": [
            "architectures",
            "hidden_size",
            "intermediate_size",
            "num_hidden_layers",
            "num_attention_heads",
            "num_key_value_heads",
            "head_dim",
            "sliding_window",
            "attn_logit_softcapping",
            "query_pre_attn_scalar",
        ],
    },
    {
        "label": "gemma_3_27b",
        "url": "https://huggingface.co/Changgil/google-gemma-3-27b-it-text/raw/4e2fb1ce4d063d7877a056b82f0485f4b568563d/config.json",
        "fields": [
            "architectures",
            "hidden_size",
            "intermediate_size",
            "num_hidden_layers",
            "num_attention_heads",
            "num_key_value_heads",
            "head_dim",
            "sliding_window",
            "attn_logit_softcapping",
            "query_pre_attn_scalar",
        ],
    },
]


def fetch(url: str) -> bytes:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "codex-gemma-config-snapshot"})
        with urllib.request.urlopen(req, timeout=60) as r:
            return r.read()
    except (urllib.error.HTTPError, urllib.error.URLError, socket.timeout) as error:
        raise SystemExit(f"Failed to fetch {url}: {error}") from error
    except Exception as error:  # pragma: no cover - defensive fallback
        raise SystemExit(f"Unexpected error while fetching {url}: {error}") from error


def main() -> None:
    for source in SOURCES:
        payload = fetch(source["url"])
        sha256 = hashlib.sha256(payload).hexdigest()
        config = json.loads(payload)
        extract = {field: config.get(field) for field in source["fields"]}
        extract["source_url"] = source["url"]
        extract["source_sha256"] = sha256
        outpath = OUTDIR / f"{source['label']}-extract.json"
        outpath.write_text(json.dumps(extract, indent=2), encoding="utf-8")
        print(f"wrote {outpath}")


if __name__ == "__main__":
    main()
