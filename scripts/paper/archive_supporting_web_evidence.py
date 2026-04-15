#!/usr/bin/env python3
"""Archive mutable web evidence used by the paper into repo-local snapshots."""

from __future__ import annotations

import hashlib
import html
import json
import re
import socket
import subprocess
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
import shutil

ROOT = Path(__file__).resolve().parents[2]
OUTDIR = ROOT / "docs" / "paper" / "evidence" / "web-2026-04-06"
RENDERER = ROOT / "scripts" / "paper" / "render_page_with_playwright.mjs"

URLS = [
    ("gemma_3_model_card", "https://ai.google.dev/gemma/docs/core/model_card_3"),
    ("gemma_family_overview", "https://developers.googleblog.com/en/gemma-explained-overview-gemma-model-family-architectures/"),
    ("stwo_2_0_0", "https://starkware.co/blog/s-two-2-0-0-prover-for-developers/"),
    ("recursive_circuit_proving", "https://starkware.co/blog/minutes-to-seconds-efficiency-gains-with-recursive-circuit-proving/"),
    ("starknet_version_releases", "https://www.starknet.io/developers/version-releases/"),
    ("strk20", "https://www.starknet.io/blog/make-all-erc-20-tokens-private-with-strk20/"),
    ("deepprove_1", "https://www.lagrange.dev/blog/deepprove-1"),
    ("deepprove_update_sep_2025", "https://www.lagrange.dev/engineering-updates/september-2025"),
    ("luminair_post", "https://starkware.co/blog/giza-x-s-two-powering-verifiable-ml-with-luminair/"),
    ("zkpytorch_product", "https://polyhedra.network/zkPyTorch"),
    ("zkpytorch_blog", "https://blog.polyhedra.network/zkpytorch/"),
    ("paradex_stwo", "https://starkware.co/blog/paradex-s-two-the-fastest-prover-meets-the-fastest-appchain/"),
]


def slugify(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", text.lower()).strip("_")


def sha256_hex(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def fetch(url: str) -> dict[str, str]:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https" or not parsed.netloc:
        raise SystemExit(f"Unsupported URL: {url!r}. Only https:// URLs are allowed.")
    try:
        result = subprocess.run(
            ["node", str(RENDERER), url],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
    except (subprocess.TimeoutExpired, OSError, socket.timeout) as error:
        raise SystemExit(f"Failed to render {url}: {error}") from error
    except Exception as error:  # pragma: no cover - defensive fallback
        raise SystemExit(f"Unexpected error while rendering {url}: {error}") from error

    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip()
        raise SystemExit(f"Failed to render {url}: {detail or f'exit code {result.returncode}'}")

    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise SystemExit(f"Failed to decode rendered snapshot for {url}: {error}") from error

    if not isinstance(payload, dict) or "html" not in payload or "text" not in payload:
        raise SystemExit(f"Rendered snapshot for {url} is missing required fields.")
    return payload


def sanitize_visible_text(text: str) -> str:
    text = text.replace("\r\n", "\n").replace("\r", "\n").strip()
    return re.sub(r"\n{3,}", "\n\n", text)


def build_snapshot_html(
    *,
    label: str,
    url: str,
    title: str,
    rendered_html: str,
    visible_text: str,
    rendered_sha256: str,
) -> bytes:
    safe_title = html.escape(title or label)
    safe_url = html.escape(url)
    safe_text = html.escape(sanitize_visible_text(visible_text))
    document = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{safe_title}</title>
  <style>
    body {{ font-family: ui-monospace, SFMono-Regular, Menlo, monospace; margin: 2rem; line-height: 1.45; color: #111; }}
    h1, h2 {{ font-family: ui-sans-serif, -apple-system, BlinkMacSystemFont, sans-serif; }}
    code {{ background: #f4f4f4; padding: 0.1rem 0.25rem; }}
    pre {{ white-space: pre-wrap; word-break: break-word; background: #f7f7f7; border: 1px solid #ddd; padding: 1rem; overflow-x: auto; }}
    .meta {{ margin-bottom: 1.5rem; }}
    .meta li {{ margin-bottom: 0.35rem; }}
  </style>
</head>
<body>
  <h1>{safe_title}</h1>
  <p>This is an inert, repo-local evidence wrapper. It stores browser-rendered visible text and content hashes so the snapshot can be inspected without executing third-party scripts or loading remote assets.</p>
  <ul class="meta">
    <li><strong>Label:</strong> <code>{html.escape(label)}</code></li>
    <li><strong>Source URL:</strong> <code>{safe_url}</code></li>
    <li><strong>Rendered HTML SHA-256:</strong> <code>{rendered_sha256}</code></li>
  </ul>
  <h2>Rendered Visible Text</h2>
  <pre>{safe_text}</pre>
</body>
</html>
"""
    return document.encode("utf-8")


def main() -> None:
    fetched: list[dict[str, str]] = []
    for label, url in URLS:
        rendered = fetch(url)
        rendered_html = rendered["html"]
        visible_text = rendered["text"]
        title = rendered.get("title", label)
        rendered_sha256 = sha256_hex(rendered_html.encode("utf-8"))
        snapshot_bytes = build_snapshot_html(
            label=label,
            url=url,
            title=title,
            rendered_html=rendered_html,
            visible_text=visible_text,
            rendered_sha256=rendered_sha256,
        )
        filename = f"{slugify(label)}.html"
        fetched.append(
            {
                "label": label,
                "url": url,
                "file": filename,
                "title": title,
                "rendered_sha256": rendered_sha256,
                "snapshot_sha256": sha256_hex(snapshot_bytes),
                "snapshot_bytes": snapshot_bytes.decode("utf-8"),
            }
        )

    with tempfile.TemporaryDirectory(dir=OUTDIR.parent) as temp_root:
        staging = Path(temp_root) / OUTDIR.name
        staging.mkdir(parents=True, exist_ok=True)
        manifest = []
        for item in fetched:
            (staging / item["file"]).write_text(item["snapshot_bytes"], encoding="utf-8")
            manifest.append(
                {
                    "label": item["label"],
                    "url": item["url"],
                    "title": item["title"],
                    "file": item["file"],
                    "rendered_sha256": item["rendered_sha256"],
                    "snapshot_sha256": item["snapshot_sha256"],
                }
            )

        (staging / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        with (staging / "manifest.tsv").open("w", encoding="utf-8") as f:
            f.write("label\turl\ttitle\tfile\trendered_sha256\tsnapshot_sha256\n")
            for item in manifest:
                f.write(
                    f"{item['label']}\t{item['url']}\t{item['title']}\t{item['file']}\t{item['rendered_sha256']}\t{item['snapshot_sha256']}\n"
                )

        backup = OUTDIR.parent / f"{OUTDIR.name}.bak"
        if backup.exists():
            shutil.rmtree(backup)
        if OUTDIR.exists():
            OUTDIR.rename(backup)
        try:
            staging.rename(OUTDIR)
        except Exception:
            if OUTDIR.exists():
                shutil.rmtree(OUTDIR)
            if backup.exists():
                backup.rename(OUTDIR)
            raise
        else:
            if backup.exists():
                shutil.rmtree(backup)

    print(f"wrote {OUTDIR / 'manifest.json'}")
    print(f"wrote {OUTDIR / 'manifest.tsv'}")


if __name__ == "__main__":
    main()
