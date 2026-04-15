#!/usr/bin/env python3
"""Generate a publication-style symbolic-work decomposition figure for Section 4."""

from __future__ import annotations

from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

ROOT = Path(__file__).resolve().parents[2]
OUTDIR = ROOT / "docs" / "paper" / "figures"
OUTDIR.mkdir(parents=True, exist_ok=True)

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
        "lines.linewidth": 1.6,
        "pdf.fonttype": 42,
        "ps.fonttype": 42,
        "svg.fonttype": "none",
        "savefig.bbox": "tight",
    }
)

C_EXP = 300
C_NORM = 30
C_NONLIN = 150


def components(t: int, d: int, h: int) -> dict[str, float]:
    arithmetic = 12 * t * d * d + 2 * t * t * d + 2 * t * d
    snark_softmax = t * t * h * C_EXP
    snark_norm = 2 * t * d * C_NORM
    snark_nonlin = 4 * t * d * C_NONLIN
    stark_softmax = t * t * h
    stark_norm = 2 * t * d
    stark_nonlin = 4 * t * d
    return {
        "snark_arithmetic": arithmetic,
        "snark_softmax": snark_softmax,
        "snark_norm": snark_norm,
        "snark_nonlin": snark_nonlin,
        "stark_arithmetic": arithmetic,
        "stark_softmax": stark_softmax,
        "stark_norm": stark_norm,
        "stark_nonlin": stark_nonlin,
    }


def main() -> None:
    configs = [
        ("GPT-2 small\nT=1024", 1024, 768, 12),
        ("GPT-2 small\nT=4096", 4096, 768, 12),
        ("Llama-2-7B style\nT=4096", 4096, 4096, 32),
        ("Llama-2-7B style\nT=32768", 32768, 4096, 32),
    ]
    records: list[tuple[str, str, str, float]] = []
    labels = []
    snark_totals = []
    stark_totals = []
    snark_parts = {"Arithmetic": [], "Softmax": [], "LayerNorm": [], "Activation": []}
    stark_parts = {"Arithmetic": [], "Softmax/lookup": [], "Norm scaling": [], "Activation scaling": []}

    for label, t, d, h in configs:
        c = components(t, d, h)
        labels.append(label)
        snark_parts["Arithmetic"].append(c["snark_arithmetic"] / 1e9)
        snark_parts["Softmax"].append(c["snark_softmax"] / 1e9)
        snark_parts["LayerNorm"].append(c["snark_norm"] / 1e9)
        snark_parts["Activation"].append(c["snark_nonlin"] / 1e9)
        stark_parts["Arithmetic"].append(c["stark_arithmetic"] / 1e9)
        stark_parts["Softmax/lookup"].append(c["stark_softmax"] / 1e9)
        stark_parts["Norm scaling"].append(c["stark_norm"] / 1e9)
        stark_parts["Activation scaling"].append(c["stark_nonlin"] / 1e9)
        snark_totals.append(
            snark_parts["Arithmetic"][-1]
            + snark_parts["Softmax"][-1]
            + snark_parts["LayerNorm"][-1]
            + snark_parts["Activation"][-1]
        )
        stark_totals.append(
            stark_parts["Arithmetic"][-1]
            + stark_parts["Softmax/lookup"][-1]
            + stark_parts["Norm scaling"][-1]
            + stark_parts["Activation scaling"][-1]
        )
        for name, value in c.items():
            records.append((label.replace("\n", " "), str(t), name, value))

    fig, axes = plt.subplots(1, 2, figsize=(7.0, 3.4), constrained_layout=True, sharey=True)
    x = list(range(len(labels)))
    width = 0.72

    snark_colors = {
        "Arithmetic": "#006BA4",
        "Softmax": "#FF800E",
        "LayerNorm": "#ABABAB",
        "Activation": "#595959",
    }
    stark_colors = {
        "Arithmetic": "#006BA4",
        "Softmax/lookup": "#FF800E",
        "Norm scaling": "#ABABAB",
        "Activation scaling": "#595959",
    }

    bottom = [0.0] * len(labels)
    for name, values in snark_parts.items():
        axes[0].bar(x, values, width=width, bottom=bottom, label=name, color=snark_colors[name])
        bottom = [b + v for b, v in zip(bottom, values)]
    axes[0].set_title("SNARK symbolic work")

    bottom = [0.0] * len(labels)
    for name, values in stark_parts.items():
        axes[1].bar(x, values, width=width, bottom=bottom, label=name, color=stark_colors[name])
        bottom = [b + v for b, v in zip(bottom, values)]
    axes[1].set_title("STARK symbolic work")

    for ax, totals in zip(axes, [snark_totals, stark_totals]):
        ax.set_xticks(x)
        ax.set_xticklabels(labels)
        ax.grid(axis="y", color="#BBBBBB", linewidth=0.6, alpha=0.35)
        ax.spines["top"].set_visible(False)
        ax.spines["right"].set_visible(False)
        for idx, total in enumerate(totals):
            ax.annotate(f"{total:.1f}", (idx, total), xytext=(0, 4), textcoords="offset points", ha="center", va="bottom", fontsize=7)

    axes[0].set_ylabel("Symbolic work (billions)")
    axes[0].legend(frameon=False, loc="upper left")
    axes[1].legend(frameon=False, loc="upper left")

    pdf_path = OUTDIR / "section4-decomposition-vs-context.pdf"
    svg_path = OUTDIR / "section4-decomposition-vs-context.svg"
    png_path = OUTDIR / "section4-decomposition-vs-context.png"
    tsv_path = OUTDIR / "section4-decomposition-vs-context.tsv"
    fig.savefig(pdf_path)
    fig.savefig(svg_path)
    fig.savefig(png_path, dpi=300)
    with tsv_path.open("w", encoding="utf-8") as f:
        f.write("configuration\tcontext_t\tcomponent\tvalue_raw\n")
        for row in records:
            f.write("\t".join(map(str, row)) + "\n")

    print(f"wrote {pdf_path}")
    print(f"wrote {svg_path}")
    print(f"wrote {png_path}")
    print(f"wrote {tsv_path}")


if __name__ == "__main__":
    main()
