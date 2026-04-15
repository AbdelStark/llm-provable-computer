This directory stores mutable external evidence that the paper freezes into repo-local snapshots.

Contents:

- `web-2026-04-06/`: inert HTML wrappers plus `manifest.json` and `manifest.tsv` for the public web pages cited in the paper's systems and infrastructure sections. Each wrapper stores browser-rendered visible text together with SHA-256 metadata, rather than preserving executable third-party page code.
- `gemma-config-snapshots/`: extracted parameter fields used by Appendix B4 and Appendix B5, derived from commit-pinned public mirror configs together with their source URLs and SHA-256 digests.

Generation scripts:

- `scripts/paper/archive_supporting_web_evidence.py`
- `scripts/paper/render_page_with_playwright.mjs`
- `scripts/paper/extract_gemma_config_snapshots.py`

These files are supporting evidence only. The main paper continues to treat archival literature, official engineering/product materials, and commit-pinned repository artifacts as distinct evidence classes. The web-evidence archive requires the Node dependency declared in `scripts/package.json`; on machines without a local Chrome installation, install Playwright's Chromium browser before regenerating the bundle.
