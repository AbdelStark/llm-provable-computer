#!/usr/bin/env python3
"""Validate cargo-audit JSON output with explicit yanked-package exceptions."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


KNOWN_WARNING_KINDS = ("unmaintained", "unsound", "yanked")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument(
        "--allow-advisory",
        action="append",
        default=[],
        metavar="RUSTSEC-...",
        help="Allow a specific advisory ID while still failing on all others.",
    )
    parser.add_argument(
        "--allow-yanked",
        action="append",
        default=[],
        metavar="CRATE@VERSION",
        help="Allow a specific yanked crate version while still failing on all others.",
    )
    return parser.parse_args()


def format_package(entry: dict) -> str:
    package = entry.get("package", {})
    return f"{package.get('name', '<unknown>')}@{package.get('version', '<unknown>')}"


def advisory_label(entry: dict) -> str:
    advisory = entry.get("advisory") or {}
    advisory_id = advisory.get("id")
    package = format_package(entry)
    if advisory_id:
        return f"{advisory_id} ({package})"
    return package


def main() -> int:
    args = parse_args()
    try:
        report = json.loads(args.report.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as err:
        print(
            "[dependency-audit] failed to read or parse cargo-audit JSON report "
            f"{args.report}: {err}",
            file=sys.stderr,
        )
        return 1

    allowed_advisories = set(args.allow_advisory)
    allowed_yanked = set(args.allow_yanked)
    seen_advisories: set[str] = set()
    seen_yanked: set[str] = set()

    vulnerabilities = report.get("vulnerabilities", {}).get("list", [])
    warnings = report.get("warnings", {})
    warning_kinds = set(warnings)
    unexpected_warning_kinds = sorted(warning_kinds.difference(KNOWN_WARNING_KINDS))

    unexpected_yanked = []
    allowed_yanked_hits = []
    for entry in warnings.get("yanked", []):
        package = format_package(entry)
        if package in allowed_yanked:
            allowed_yanked_hits.append(package)
            seen_yanked.add(package)
        else:
            unexpected_yanked.append(package)

    failures: list[str] = []
    for entry in vulnerabilities:
        advisory_id = (entry.get("advisory") or {}).get("id")
        if advisory_id and advisory_id in allowed_advisories:
            seen_advisories.add(advisory_id)
            continue
        failures.append(f"vulnerability: {advisory_label(entry)}")
    for kind in ("unmaintained", "unsound"):
        for entry in warnings.get(kind, []):
            advisory_id = (entry.get("advisory") or {}).get("id")
            if advisory_id and advisory_id in allowed_advisories:
                seen_advisories.add(advisory_id)
                continue
            failures.append(f"{kind}: {advisory_label(entry)}")
    for package in unexpected_yanked:
        failures.append(f"yanked: {package}")
    for kind in unexpected_warning_kinds:
        failures.append(f"unexpected warning category: {kind}")
    for advisory_id in sorted(allowed_advisories.difference(seen_advisories)):
        failures.append(f"stale allowed advisory: {advisory_id}")
    for package in sorted(allowed_yanked.difference(seen_yanked)):
        failures.append(f"stale allowed yanked package: {package}")

    if failures:
        print("[dependency-audit] unexpected cargo-audit findings:", file=sys.stderr)
        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)
        return 1

    if seen_advisories:
        print(
            "[dependency-audit] allowed advisories: "
            + ", ".join(sorted(seen_advisories))
        )
    if allowed_yanked_hits:
        unique_hits = sorted(set(allowed_yanked_hits))
        print(
            "[dependency-audit] allowed yanked crates: "
            + ", ".join(unique_hits)
        )

    return 0


if __name__ == "__main__":
    sys.exit(main())
