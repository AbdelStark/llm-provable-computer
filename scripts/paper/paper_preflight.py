#!/usr/bin/env python3
"""Publication preflight checks for docs/paper artifacts.

Checks:
1) citation integrity (numeric in-text citations must exist in local references section),
2) immutable-link policy for this repository's GitHub links (commit-pinned only),
3) figure/link cross-reference existence for local file links,
4) source-note presence in appendix-system-comparison,
5) backend appendix timing/size consistency against frozen artifact indices,
6) unresolved publication snapshot placeholder detection.
"""

from __future__ import annotations

import argparse
import pathlib
import re
import sys
from dataclasses import dataclass, field
from urllib.parse import urlparse


PUBLICATION_METADATA_FILES = [
    "docs/paper/PUBLICATION_RELEASE.md",
    "docs/paper/submission-v4-2026-04-11/BUNDLE_INDEX.md",
    "docs/paper/submission-v4-2026-04-11/REPRODUCIBILITY_NOTE.md",
]

PAPER_FILES = [
    "docs/paper/stark-transformer-alignment-2026.md",
    "docs/paper/appendix-system-comparison.md",
    "docs/paper/appendix-scaling-companion.md",
    "docs/paper/appendix-backend-artifact-comparison.md",
    "docs/paper/appendix-influence-realization.md",
    *PUBLICATION_METADATA_FILES,
]

SNAPSHOT_FIELD_PREFIXES = (
    "Canonical publication snapshot",
    "Canonical repository snapshot",
)

HARD_SNAPSHOT_PLACEHOLDER_TOKENS = ("TBD_SNAPSHOT_SHA",)
SOFT_SNAPSHOT_PLACEHOLDER_TOKENS = (
    "PENDING_SNAPSHOT_SHA",
    "Pending.",
    "Pending:",
)

LOCAL_REPOS = {
    ("omarespejel", "llm-provable-computer"),
    ("omarespejel", "provable-transformer-vm"),
}


@dataclass
class Findings:
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def error(self, msg: str) -> None:
        self.errors.append(msg)

    def warn(self, msg: str) -> None:
        self.warnings.append(msg)


def is_commitish(ref: str) -> bool:
    # GitHub short/long SHA references.
    return bool(re.fullmatch(r"[0-9a-f]{7,40}", ref))


def split_body_refs(text: str) -> tuple[str, str]:
    marker = "\n## References\n"
    if marker in text:
        return text.split(marker, 1)
    return text, ""


def parse_reference_ids(refs_text: str) -> set[int]:
    ids: set[int] = set()
    for line in refs_text.splitlines():
        m_num = re.match(r"^\s*(\d+)\.\s", line)
        if m_num:
            ids.add(int(m_num.group(1)))
            continue
        m_br = re.match(r"^\s*-\s*\[(\d+)\]\s", line)
        if m_br:
            ids.add(int(m_br.group(1)))
    return ids


def expand_citation_token(token: str) -> list[int]:
    out: list[int] = []
    for part in re.split(r"\s*,\s*", token):
        if "-" in part:
            a, b = re.split(r"\s*-\s*", part, 1)
            if a.isdigit() and b.isdigit():
                ai, bi = int(a), int(b)
                if ai <= bi:
                    out.extend(range(ai, bi + 1))
                else:
                    out.extend(range(bi, ai + 1))
            continue
        if part.isdigit():
            out.append(int(part))
    return out


def parse_citation_ids(body_text: str) -> set[int]:
    ids: set[int] = set()
    # Numeric citation styles: [1], [1, 2], [24-31]
    for m in re.finditer(r"\[(\d+(?:\s*[-,]\s*\d+)*)\]", body_text):
        for n in expand_citation_token(m.group(1)):
            ids.add(n)
    return ids


def extract_markdown_links(text: str) -> list[str]:
    links: list[str] = []
    # Inline image + inline links.
    for pat in (
        r"!\[[^\]]*\]\(([^)]+)\)",
        r"(?<!!)\[[^\]]*\]\(([^)]+)\)",
        r"<(https?://[^>\s]+)>",
    ):
        for m in re.finditer(pat, text):
            links.append(m.group(1).strip())
    return links


def check_local_relative_links(
    file_path: pathlib.Path, links: list[str], findings: Findings
) -> None:
    for link in links:
        if link.startswith(("http://", "https://", "mailto:", "#", "data:")):
            continue
        # Skip title fragment.
        raw = link.split("#", 1)[0].strip()
        if not raw:
            continue
        target = (file_path.parent / raw).resolve()
        if not target.exists():
            findings.error(
                f"{file_path}: local link target does not exist: {link}"
            )


def local_repo_url_path(url: str) -> tuple[str, str, str] | None:
    """Return (kind, ref, path) for local repo GitHub/raw URL or None."""
    parsed = urlparse(url)
    host = parsed.netloc.lower()
    path_parts = [p for p in parsed.path.split("/") if p]

    if host == "github.com":
        if len(path_parts) < 4:
            return None
        owner, repo, kind, ref = path_parts[:4]
        if (owner, repo) not in LOCAL_REPOS or kind not in {"blob", "tree"}:
            return None
        rel_path = "/".join(path_parts[4:]) if len(path_parts) > 4 else ""
        return kind, ref, rel_path

    if host == "raw.githubusercontent.com":
        if len(path_parts) < 4:
            return None
        owner, repo, ref = path_parts[:3]
        if (owner, repo) not in LOCAL_REPOS:
            return None
        rel_path = "/".join(path_parts[3:])
        return "raw", ref, rel_path

    return None


def check_immutable_local_repo_links(
    source_file: pathlib.Path, links: list[str], repo_root: pathlib.Path, findings: Findings
) -> None:
    for link in links:
        if not link.startswith(("http://", "https://")):
            continue
        parsed = local_repo_url_path(link)
        if not parsed:
            continue
        kind, ref, rel_path = parsed
        if not is_commitish(ref):
            findings.error(
                f"{source_file}: local repository link is not commit-pinned: {link}"
            )
        if kind == "blob" and not rel_path:
            findings.error(
                f"{source_file}: local repository blob link has no file path: {link}"
            )
        if rel_path:
            local_target = repo_root / rel_path
            if not local_target.exists():
                findings.error(
                    f"{source_file}: referenced local-repo path not found in workspace: {link}"
                )


def run_file_checks(file_path: pathlib.Path, repo_root: pathlib.Path, findings: Findings) -> None:
    text = file_path.read_text(encoding="utf-8")
    body, refs = split_body_refs(text)
    ref_ids = parse_reference_ids(refs)
    cite_ids = parse_citation_ids(body)

    # Only enforce citation-ID integrity when the file has a local References section.
    if ref_ids:
        missing = sorted(n for n in cite_ids if n not in ref_ids)
        if missing:
            findings.error(
                f"{file_path}: citations reference missing IDs in local References section: {missing}"
            )
        unused = sorted(n for n in ref_ids if n not in cite_ids)
        if unused:
            findings.warn(
                f"{file_path}: unused reference IDs (review for hygiene): {unused}"
            )

    links = extract_markdown_links(text)
    check_local_relative_links(file_path, links, findings)
    check_immutable_local_repo_links(file_path, links, repo_root, findings)


def check_appendix_source_note(repo_root: pathlib.Path, findings: Findings) -> None:
    path = repo_root / "docs/paper/appendix-system-comparison.md"
    text = path.read_text(encoding="utf-8")
    if "Sources:" not in text:
        findings.error(f"{path}: missing standalone source note (expected 'Sources: ...').")


def check_publication_snapshot_placeholders(
    repo_root: pathlib.Path, findings: Findings
) -> None:
    for rel_path in PUBLICATION_METADATA_FILES:
        path = repo_root / rel_path
        if not path.exists():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            findings.error(
                f"{path}: failed to read publication metadata for snapshot placeholder checks: {exc}"
            )
            continue
        for token in HARD_SNAPSHOT_PLACEHOLDER_TOKENS:
            if token in text:
                findings.error(
                    f"{path}: unresolved publication snapshot placeholder {token!r}; "
                    "replace it before paper preflight."
                )
        snapshot_field_text = "\n".join(iter_snapshot_field_lines(text))
        for token in SOFT_SNAPSHOT_PLACEHOLDER_TOKENS:
            if token in snapshot_field_text:
                findings.error(
                    f"{path}: unresolved publication snapshot placeholder {token!r}; "
                    "replace it before paper preflight."
                )


def iter_snapshot_field_lines(text: str):
    lines = text.splitlines()
    for index, line in enumerate(lines):
        stripped = line.strip()
        if not any(stripped.startswith(prefix) for prefix in SNAPSHOT_FIELD_PREFIXES):
            continue
        yield line
        for continuation in lines[index + 1 :]:
            continuation = continuation.strip()
            if not continuation or continuation.startswith("#"):
                break
            yield continuation


def parse_markdown_table_after_heading(text: str, heading: str) -> list[list[str]]:
    lines = text.splitlines()
    start = None
    normalized_heading = heading.strip().lower()
    for i, line in enumerate(lines):
        if line.strip().lower() == normalized_heading:
            start = i + 1
            break
    if start is None:
        raise ValueError(f"heading not found: {heading}")

    rows: list[list[str]] = []
    in_table = False
    for line in lines[start:]:
        stripped = line.strip()
        if not stripped:
            if in_table:
                break
            continue
        if not stripped.startswith("|"):
            if in_table:
                break
            continue
        in_table = True
        cells = [cell.strip() for cell in stripped.strip("|").split("|")]
        rows.append(cells)
    return rows


def normalize_table_header(cell: str) -> str:
    return re.sub(r"\s+", " ", cell.strip().strip("`").lower())


def parse_index_sizes(index_text: str) -> dict[str, int]:
    out: dict[str, int] = {}
    try:
        rows = parse_markdown_table_after_heading(index_text, "## Primary Artifacts")
    except ValueError:
        return out
    if len(rows) < 3:
        return out
    header_map = {
        normalize_table_header(name): idx for idx, name in enumerate(rows[0])
    }
    try:
        artifact_idx = header_map["artifact"]
        size_idx = header_map["size (bytes)"]
    except KeyError:
        return out
    # Skip header + separator.
    for row in rows[2:]:
        if len(row) <= max(artifact_idx, size_idx):
            continue
        artifact = row[artifact_idx].strip("`")
        size_cell = row[size_idx]
        digits = re.sub(r"[^0-9]", "", size_cell)
        if not digits:
            continue
        out[artifact] = int(digits)
    return out


def parse_index_timings(index_text: str) -> dict[str, int]:
    out: dict[str, int] = {}
    try:
        rows = parse_markdown_table_after_heading(index_text, "## Timing Summary (seconds)")
    except ValueError:
        return out
    if len(rows) < 3:
        return out
    header_map = {
        normalize_table_header(name): idx for idx, name in enumerate(rows[0])
    }
    try:
        label_idx = header_map["label"]
        seconds_idx = header_map["seconds"]
    except KeyError:
        return out
    # Skip header + separator.
    for row in rows[2:]:
        if len(row) <= max(label_idx, seconds_idx):
            continue
        label = row[label_idx].strip("`")
        seconds_cell = row[seconds_idx]
        digits = re.sub(r"[^0-9]", "", seconds_cell)
        if not digits:
            continue
        out[label] = int(digits)
    return out


def parse_appendix_backend_rows(appendix_text: str) -> dict[tuple[str, str], tuple[int, int, int]]:
    out: dict[tuple[str, str], tuple[int, int, int]] = {}
    try:
        rows = parse_markdown_table_after_heading(
            appendix_text, "## Table C1. Frozen artifact comparison by backend and scope"
        )
    except ValueError:
        return out
    if len(rows) < 3:
        return out
    header_map = {
        normalize_table_header(name): idx for idx, name in enumerate(rows[0])
    }

    def first_matching_header(*aliases: str) -> int:
        for alias in aliases:
            key = normalize_table_header(alias)
            if key in header_map:
                return header_map[key]
        raise KeyError(aliases[0])

    try:
        artifact_idx = first_matching_header("Artifact")
        backend_idx = first_matching_header("Backend")
        prove_idx = first_matching_header("Prove")
        verify_idx = first_matching_header("Verify")
        size_idx = first_matching_header("Proof size", "Proof size (bytes)", "Size (bytes)")
    except KeyError:
        return out
    # Skip header + separator.
    for row in rows[2:]:
        if len(row) <= max(artifact_idx, backend_idx, prove_idx, verify_idx, size_idx):
            continue
        artifact = row[artifact_idx].strip().strip("`")
        backend = row[backend_idx].strip().strip("`")
        prove_digits = re.sub(r"[^0-9]", "", row[prove_idx])
        verify_digits = re.sub(r"[^0-9]", "", row[verify_idx])
        size_digits = re.sub(r"[^0-9]", "", row[size_idx])
        if not (prove_digits and verify_digits and size_digits):
            continue
        out[(artifact, backend)] = (int(prove_digits), int(verify_digits), int(size_digits))
    return out


def check_backend_appendix_consistency(repo_root: pathlib.Path, findings: Findings) -> None:
    appendix_path = repo_root / "docs/paper/appendix-backend-artifact-comparison.md"
    prod_index_path = (
        repo_root
        / "docs/paper/artifacts/production-v1-2026-04-04/APPENDIX_ARTIFACT_INDEX.md"
    )
    stwo_index_path = (
        repo_root
        / "docs/paper/artifacts/stwo-experimental-v1-2026-04-06/APPENDIX_ARTIFACT_INDEX.md"
    )

    for required_path in (appendix_path, prod_index_path, stwo_index_path):
        if not required_path.exists():
            findings.error(
                f"{required_path}: missing required file for backend artifact consistency check."
            )
            return

    try:
        appendix_text = appendix_path.read_text(encoding="utf-8")
        prod_text = prod_index_path.read_text(encoding="utf-8")
        stwo_text = stwo_index_path.read_text(encoding="utf-8")
    except OSError as exc:
        findings.error(
            "failed to read backend artifact consistency inputs "
            f"({appendix_path}, {prod_index_path}, {stwo_index_path}): {exc}"
        )
        return

    appendix_rows = parse_appendix_backend_rows(appendix_text)
    if not appendix_rows:
        findings.error(
            f"{appendix_path}: failed to parse Table C1 rows for backend artifact consistency checks."
        )
        return

    prod_sizes = parse_index_sizes(prod_text)
    prod_timings = parse_index_timings(prod_text)
    stwo_sizes = parse_index_sizes(stwo_text)
    stwo_timings = parse_index_timings(stwo_text)

    required_prod_timing_keys = [
        "prove_addition",
        "verify_addition",
        "prove_dot_product",
        "verify_dot_product",
        "prove_single_neuron",
        "verify_single_neuron",
    ]
    required_prod_size_keys = [
        "addition.proof.json",
        "dot_product.proof.json",
        "single_neuron.proof.json",
    ]
    required_stwo_timing_keys = [
        "prove_addition_stwo",
        "verify_addition_stwo",
        "prove_shared_normalization_stwo",
        "verify_shared_normalization_stwo",
        "prove_gemma_block_v4_stwo",
        "verify_gemma_block_v4_stwo",
        "prove_decoding_demo_stwo",
        "verify_decoding_demo_stwo",
    ]
    required_stwo_size_keys = [
        "addition.stwo.proof.json",
        "shared-normalization.stwo.proof.json",
        "gemma_block_v4.stwo.proof.json",
        "decoding.stwo.chain.json",
    ]

    missing_prod_timing = sorted(k for k in required_prod_timing_keys if k not in prod_timings)
    missing_prod_sizes = sorted(k for k in required_prod_size_keys if k not in prod_sizes)
    missing_stwo_timing = sorted(k for k in required_stwo_timing_keys if k not in stwo_timings)
    missing_stwo_sizes = sorted(k for k in required_stwo_size_keys if k not in stwo_sizes)
    if missing_prod_timing:
        findings.error(
            f"{prod_index_path}: missing timing keys required for Appendix C consistency check: "
            f"{missing_prod_timing}"
        )
    if missing_prod_sizes:
        findings.error(
            f"{prod_index_path}: missing artifact-size keys required for Appendix C consistency check: "
            f"{missing_prod_sizes}"
        )
    if missing_stwo_timing:
        findings.error(
            f"{stwo_index_path}: missing timing keys required for Appendix C consistency check: "
            f"{missing_stwo_timing}"
        )
    if missing_stwo_sizes:
        findings.error(
            f"{stwo_index_path}: missing artifact-size keys required for Appendix C consistency check: "
            f"{missing_stwo_sizes}"
        )
    if missing_prod_timing or missing_prod_sizes or missing_stwo_timing or missing_stwo_sizes:
        return

    # NOTE: This mapping is intentionally strict for frozen-artifact validation.
    # Table C1 artifact/backend labels (after backtick stripping) and frozen index
    # timing/size keys must match these entries exactly. If naming conventions or
    # compared artifact rows change, update this mapping explicitly.
    expected: dict[tuple[str, str], tuple[int, int, int]] = {
        ("addition", "vanilla"): (
            prod_timings["prove_addition"],
            prod_timings["verify_addition"],
            prod_sizes["addition.proof.json"],
        ),
        ("dot_product", "vanilla"): (
            prod_timings["prove_dot_product"],
            prod_timings["verify_dot_product"],
            prod_sizes["dot_product.proof.json"],
        ),
        ("single_neuron", "vanilla"): (
            prod_timings["prove_single_neuron"],
            prod_timings["verify_single_neuron"],
            prod_sizes["single_neuron.proof.json"],
        ),
        ("addition", "stwo"): (
            stwo_timings["prove_addition_stwo"],
            stwo_timings["verify_addition_stwo"],
            stwo_sizes["addition.stwo.proof.json"],
        ),
        ("shared-normalization-demo", "stwo"): (
            stwo_timings["prove_shared_normalization_stwo"],
            stwo_timings["verify_shared_normalization_stwo"],
            stwo_sizes["shared-normalization.stwo.proof.json"],
        ),
        ("gemma_block_v4", "stwo"): (
            stwo_timings["prove_gemma_block_v4_stwo"],
            stwo_timings["verify_gemma_block_v4_stwo"],
            stwo_sizes["gemma_block_v4.stwo.proof.json"],
        ),
        ("decoding_demo", "stwo"): (
            stwo_timings["prove_decoding_demo_stwo"],
            stwo_timings["verify_decoding_demo_stwo"],
            stwo_sizes["decoding.stwo.chain.json"],
        ),
    }

    for key, expected_values in expected.items():
        if key not in appendix_rows:
            findings.error(
                f"{appendix_path}: missing Table C1 row for artifact/backend {key!r}."
            )
            continue
        found_values = appendix_rows[key]
        if found_values != expected_values:
            findings.error(
                f"{appendix_path}: Table C1 mismatch for {key!r}: found prove/verify/size={found_values}, "
                f"expected={expected_values} from frozen artifact indices."
            )

    unexpected_keys = sorted(set(appendix_rows) - set(expected))
    for key in unexpected_keys:
        findings.error(
            f"{appendix_path}: unexpected Table C1 row for artifact/backend {key!r}; "
            "no matching frozen artifact index entry."
        )


def main() -> int:
    parser = argparse.ArgumentParser(description="Run publication preflight checks for docs/paper.")
    parser.add_argument(
        "--repo-root",
        default=".",
        help="Repository root path (default: current directory).",
    )
    args = parser.parse_args()

    repo_root = pathlib.Path(args.repo_root).resolve()
    findings = Findings()

    for rel in PAPER_FILES:
        path = repo_root / rel
        if not path.exists():
            findings.error(f"missing expected paper file: {path}")
            continue
        run_file_checks(path, repo_root, findings)

    check_appendix_source_note(repo_root, findings)
    check_backend_appendix_consistency(repo_root, findings)
    check_publication_snapshot_placeholders(repo_root, findings)

    if findings.warnings:
        print("Warnings:")
        for w in findings.warnings:
            print(f"  - {w}")

    if findings.errors:
        print("Errors:")
        for e in findings.errors:
            print(f"  - {e}")
        return 1

    print("paper preflight: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
