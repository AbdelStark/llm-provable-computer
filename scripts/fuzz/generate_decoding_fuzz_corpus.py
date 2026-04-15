#!/usr/bin/env python3
import argparse
import json
import os
import pathlib
import subprocess
import sys
import tomllib

ROOT = pathlib.Path(__file__).resolve().parents[2]
CORPUS = ROOT / "fuzz" / "corpus"
FUZZ_TOOLCHAIN_TOML = ROOT / "fuzz" / "rust-toolchain.toml"
PHASE29_CURATED_CORPUS = (
    CORPUS / "phase29_recursive_compression_input_contract" / "valid_phase29.json"
)
RUN_TIMEOUT_SECONDS = 300
DEFAULT_RUST_TOOLCHAIN = "nightly-2025-07-14"


def env_flag_is_true(name: str) -> bool:
    value = os.environ.get(name)
    if value is None:
        return False
    return value.strip().lower() not in {"", "0", "false", "no", "off"}


def normalized_toolchain(value: str) -> str:
    return value.lstrip("+")


def load_rust_toolchain() -> str:
    in_ci = env_flag_is_true("CI") or env_flag_is_true("GITHUB_ACTIONS")
    env_toolchain = os.environ.get("FUZZ_RUST_TOOLCHAIN")
    if env_toolchain and not in_ci:
        return normalized_toolchain(env_toolchain)
    try:
        with FUZZ_TOOLCHAIN_TOML.open("rb") as handle:
            config = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as error:
        if in_ci:
            raise SystemExit(
                f"failed to read required CI fuzz toolchain file {FUZZ_TOOLCHAIN_TOML}: {error}"
            ) from error
        print(
            f"warning: failed to read {FUZZ_TOOLCHAIN_TOML}: {error}; "
            f"falling back to {DEFAULT_RUST_TOOLCHAIN}",
            file=sys.stderr,
        )
        return DEFAULT_RUST_TOOLCHAIN
    channel = config.get("toolchain", {}).get("channel")
    if not isinstance(channel, str) or not channel:
        if in_ci:
            raise SystemExit(
                f"{FUZZ_TOOLCHAIN_TOML} is missing required toolchain.channel in CI"
            )
        print(
            f"warning: {FUZZ_TOOLCHAIN_TOML} is missing toolchain.channel; "
            f"falling back to {DEFAULT_RUST_TOOLCHAIN}",
            file=sys.stderr,
        )
        return DEFAULT_RUST_TOOLCHAIN
    return normalized_toolchain(channel)


RUST_TOOLCHAIN = load_rust_toolchain()


def run(*args: str) -> None:
    try:
        subprocess.run(
            args,
            cwd=ROOT,
            check=True,
            timeout=RUN_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired as error:
        raise SystemExit(
            f"command timed out after {RUN_TIMEOUT_SECONDS}s: {' '.join(args)}"
        ) from error
    except subprocess.CalledProcessError as error:
        raise SystemExit(
            f"command failed with exit code {error.returncode}: {' '.join(args)}"
        ) from error


def write_json(path: pathlib.Path, value: object) -> None:
    serialized = json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n"
    path.write_text(serialized)
    if path.stat().st_size == 0:
        raise SystemExit(f"generated empty fuzz corpus file: {path}")
    json.loads(path.read_text())


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate curated fuzz corpus inputs for decoding-related targets."
    )
    parser.add_argument(
        "--output-root",
        type=pathlib.Path,
        default=CORPUS,
        help="Corpus root directory to populate. Defaults to fuzz/corpus.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    corpus_root = args.output_root.resolve()

    phase12_path = corpus_root / "phase12_decoding_manifest" / "valid_phase12.json"
    phase14_path = corpus_root / "phase14_decoding_manifest" / "valid_phase14.json"
    artifact_path = corpus_root / "phase12_shared_lookup_artifact" / "valid_artifact.json"
    phase29_path = (
        corpus_root / "phase29_recursive_compression_input_contract" / "valid_phase29.json"
    )
    phase30_path = (
        corpus_root / "phase30_decoding_step_proof_envelope_manifest" / "valid_phase30.json"
    )

    phase12_path.parent.mkdir(parents=True, exist_ok=True)
    phase14_path.parent.mkdir(parents=True, exist_ok=True)
    artifact_path.parent.mkdir(parents=True, exist_ok=True)
    phase29_path.parent.mkdir(parents=True, exist_ok=True)
    phase30_path.parent.mkdir(parents=True, exist_ok=True)

    run(
        "cargo",
        f"+{RUST_TOOLCHAIN}",
        "run",
        "--quiet",
        "--features",
        "stwo-backend",
        "--bin",
        "tvm",
        "--",
        "prove-stwo-decoding-family-demo",
        "--output",
        str(phase12_path),
    )
    run(
        "cargo",
        f"+{RUST_TOOLCHAIN}",
        "run",
        "--quiet",
        "--features",
        "stwo-backend",
        "--bin",
        "tvm",
        "--",
        "prove-stwo-decoding-chunked-history-demo",
        "--output",
        str(phase14_path),
    )

    phase12 = json.loads(phase12_path.read_text())
    write_json(phase12_path, phase12)

    phase14 = json.loads(phase14_path.read_text())
    write_json(phase14_path, phase14)

    lookup_artifacts = phase12.get("shared_lookup_artifacts", [])
    if not isinstance(lookup_artifacts, list) or not lookup_artifacts:
        raise SystemExit("phase12 corpus generation did not produce shared lookup artifacts")
    steps = phase12.get("steps", [])
    if not isinstance(steps, list) or not steps:
        raise SystemExit("phase12 corpus generation did not produce decoding steps")
    if "layout" not in phase12:
        raise SystemExit("phase12 corpus generation did not produce layout")
    first_step = steps[0]
    if not isinstance(first_step, dict):
        raise SystemExit(
            f"phase12 corpus generation produced a non-object first step: {first_step!r}"
        )
    referenced_commitment = first_step.get("shared_lookup_artifact_commitment")
    if not isinstance(referenced_commitment, str) or not referenced_commitment:
        raise SystemExit(
            "phase12 corpus generation first step is missing shared_lookup_artifact_commitment"
        )
    matching_artifacts = [
        artifact
        for artifact in lookup_artifacts
        if isinstance(artifact, dict)
        and artifact.get("artifact_commitment") == referenced_commitment
        and "layout_commitment" in artifact
    ]
    if len(matching_artifacts) != 1:
        raise SystemExit(
            "phase12 corpus generation must produce exactly one shared lookup artifact "
            f"matching first step commitment {referenced_commitment!r}, found "
            f"{len(matching_artifacts)} in {lookup_artifacts!r}"
        )
    first_artifact = matching_artifacts[0]

    artifact_input = {
        "layout": phase12["layout"],
        "expected_layout_commitment": first_artifact["layout_commitment"],
        "artifact": first_artifact,
    }
    write_json(artifact_path, artifact_input)

    run(
        "cargo",
        f"+{RUST_TOOLCHAIN}",
        "run",
        "--quiet",
        "--features",
        "stwo-backend",
        "--bin",
        "tvm",
        "--",
        "prepare-stwo-decoding-step-envelope-manifest",
        "--proof",
        str(phase12_path),
        "-o",
        str(phase30_path),
    )
    phase30 = json.loads(phase30_path.read_text())
    phase30_input = {
        "manifest": phase30,
        "chain": phase12,
    }
    write_json(phase30_path, phase30_input)

    if not PHASE29_CURATED_CORPUS.is_file():
        raise SystemExit(f"missing checked-in Phase 29 corpus seed: {PHASE29_CURATED_CORPUS}")

    run(
        "cargo",
        f"+{RUST_TOOLCHAIN}",
        "run",
        "--quiet",
        "--features",
        "stwo-backend",
        "--bin",
        "tvm",
        "--",
        "verify-stwo-recursive-compression-input-contract",
        "--input",
        str(PHASE29_CURATED_CORPUS),
    )

    phase29 = json.loads(PHASE29_CURATED_CORPUS.read_text())
    write_json(phase29_path, phase29)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
