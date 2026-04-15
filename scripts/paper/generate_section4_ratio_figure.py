#!/usr/bin/env python3
"""Generate a publication-style Section 4 scaling figure.

This figure is intentionally conservative:
- The dense curve uses the GPT-2-small symbolic model from Section 4.
- The sparse curve is a representative Gemma-style sparse attention schedule
  under the same symbolic constants: 5 local layers for every 1 global layer,
  with a sliding window W=1024. It is meant to visualize the architectural
  damping effect of sparse long-context attention, not to claim exact numbers
  for one released Gemma checkpoint.
"""

from __future__ import annotations

from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

ROOT = Path(__file__).resolve().parents[2]
OUTDIR = ROOT / "docs" / "paper" / "figures"
OUTDIR.mkdir(parents=True, exist_ok=True)

# Publication-oriented defaults.
plt.style.use("tableau-colorblind10")
plt.rcParams.update(
    {
        "font.family": "serif",
        "font.serif": ["STIX Two Text", "Times New Roman", "DejaVu Serif"],
        "mathtext.fontset": "stix",
        "font.size": 8,
        "axes.labelsize": 8,
        "axes.titlesize": 9,
        "legend.fontsize": 7,
        "xtick.labelsize": 7,
        "ytick.labelsize": 7,
        "axes.linewidth": 0.8,
        "lines.linewidth": 2.0,
        "lines.markersize": 4.5,
        "pdf.fonttype": 42,
        "ps.fonttype": 42,
        "svg.fonttype": "none",
        "savefig.bbox": "tight",
    }
)

# Stylized constants from the paper.
C_EXP = 300
C_NORM = 30
C_NONLIN = 150

# GPT-2-small-style dense parameters from Section 4.
D = 768
H = 12

# Representative Gemma-style sparse schedule for the figure.
LOCAL_PER_CYCLE = 5
GLOBAL_PER_CYCLE = 1
WINDOW = 1024


def dense_ratio(t: int, d: int = D, h: int = H) -> float:
    """GPT-style dense attention symbolic ratio for one representative layer."""
    arith = 12 * t * d * d + 2 * t * t * d + 2 * t * d
    snark = arith + (t * t * h * C_EXP) + (2 * t * d * C_NORM) + (4 * t * d * C_NONLIN)
    stark = arith + (t * t * h) + (2 * t * d) + (4 * t * d)
    return snark / stark


def sparse_gemma_style_ratio(t: int, d: int = D, h: int = H, window: int = WINDOW) -> float:
    """Representative Gemma-style sparse attention ratio.

    This keeps the GPT-style linear algebra and nonlinear constants, but replaces
    fully global attention with a 5:1 local:global schedule and a finite sliding
    window for the local layers. The purpose is to show how released sparse
    long-context architectures damp the dense-attention gap.
    """
    w_eff = min(t, window)
    cycle = LOCAL_PER_CYCLE + GLOBAL_PER_CYCLE
    avg_attention_span = (GLOBAL_PER_CYCLE * (t * t) + LOCAL_PER_CYCLE * (t * w_eff)) / cycle

    arith = 12 * t * d * d + 2 * d * avg_attention_span + 2 * t * d
    softmax_events = h * avg_attention_span
    snark = arith + (softmax_events * C_EXP) + (2 * t * d * C_NORM) + (4 * t * d * C_NONLIN)
    stark = arith + softmax_events + (2 * t * d) + (4 * t * d)
    return snark / stark


def main() -> None:
    contexts = [128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536, 131072]
    dense = [dense_ratio(t) for t in contexts]
    sparse = [sparse_gemma_style_ratio(t) for t in contexts]
    dense_asymptote = (2 * D + H * C_EXP) / (2 * D + H)

    fig, ax = plt.subplots(figsize=(6.6, 3.2), constrained_layout=True)

    ax.plot(contexts, dense, marker="o", color="#006BA4", label="Dense GPT-style")
    ax.plot(
        contexts,
        sparse,
        marker="s",
        linestyle="--",
        color="#B24745",
        label="Sparse Gemma-style (5:1 local/global, W=1024)",
    )
    ax.axhline(
        dense_asymptote,
        linestyle=":",
        linewidth=1.4,
        color="#444444",
        label=f"Dense asymptote ({dense_asymptote:.2f}x)",
    )

    ax.set_xscale("log", base=2)
    ax.set_xlabel("Context length T")
    ax.set_ylabel("SNARK / STARK symbolic ratio")
    ax.set_ylim(1.0, max(dense) * 1.08)
    ax.grid(axis="y", color="#BBBBBB", linewidth=0.6, alpha=0.35)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.legend(frameon=False, loc="upper left")
    ax.set_xticks(contexts)
    ax.set_xticklabels([str(t) for t in contexts], rotation=25, ha="right")

    # Light endpoint annotations improve readability in print without clutter.
    ax.annotate(f"{dense[-1]:.2f}x", (contexts[-1], dense[-1]), xytext=(6, 0), textcoords="offset points", va="center", color="#006BA4")
    ax.annotate(f"{sparse[-1]:.2f}x", (contexts[-1], sparse[-1]), xytext=(6, -10), textcoords="offset points", va="center", color="#B24745")
    ax.annotate(
        f"{dense_asymptote:.2f}x ceiling",
        (contexts[1], dense_asymptote),
        xytext=(0, 4),
        textcoords="offset points",
        va="bottom",
        color="#444444",
    )

    pdf_path = OUTDIR / "section4-ratio-vs-context.pdf"
    svg_path = OUTDIR / "section4-ratio-vs-context.svg"
    png_path = OUTDIR / "section4-ratio-vs-context.png"
    tsv_path = OUTDIR / "section4-ratio-vs-context.tsv"
    fig.savefig(pdf_path)
    fig.savefig(svg_path)
    fig.savefig(png_path, dpi=300)
    with tsv_path.open("w", encoding="utf-8") as f:
        f.write("context_t\tdense_gpt_style_ratio\tsparse_gemma_style_ratio\n")
        for t, d_ratio, s_ratio in zip(contexts, dense, sparse):
            f.write(f"{t}\t{d_ratio:.6f}\t{s_ratio:.6f}\n")

    print(f"wrote {pdf_path}")
    print(f"wrote {svg_path}")
    print(f"wrote {png_path}")
    print(f"wrote {tsv_path}")


if __name__ == "__main__":
    main()
