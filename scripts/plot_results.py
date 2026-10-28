"""Figures for the thesis: residual-risk curves R(k)/R(0) of group V.

Presentation only; needs matplotlib, which the AAPEF runtime does not use, so
run it from an environment that has it (e.g. the NASim venv):

    python scripts/plot_results.py out/policies/V --out reports/figures

Reads <run>/<structure>-m<m>/curves.csv (regenerate with
scripts/run_group_v.sh if absent). For each eval model it draws one panel per
m: mean over networks of R(k)/R(0), the random policy first averaged over its
seeds within each network. Colours: validated categorical order of the
dataviz reference palette; each series also has its own marker, so identity
never rests on colour alone; the numbers are in reports/KetQua_NhomV.md.
"""

import argparse
import csv
import glob
import os
import statistics
from collections import defaultdict

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

SERIES = [  # (policy label, legend text, colour, marker)
    ("context-greedy(epss)", "Theo ngữ cảnh (EPSS)", "#2a78d6", "o"),
    ("context-greedy(cvss)", "Theo ngữ cảnh (CVSS)", "#eb6834", "s"),
    ("epss", "EPSS", "#1baf7a", "^"),
    ("kev-first", "KEV-trước", "#eda100", "D"),
    ("cvss-base", "CVSS-Base", "#e87ba4", "v"),
    ("random", "Ngẫu nhiên", "#8a8985", None),
]
TEXT, MUTED, GRID = "#0b0b0b", "#52514e", "#e4e3df"
EVAL_NAME = {"epss": "M-EPSS", "kev": "M-KEV", "cvss": "M-CVSS"}


def label(r):
    pm = r["policy_model"]
    return r["policy"] + (f"({pm})" if pm and r["policy"] != "optimal" else "")


def mean_curves(run, m):
    """{(eval model, policy): [mean R(k)/R(0) over networks]}"""
    acc = defaultdict(lambda: defaultdict(lambda: defaultdict(list)))
    for path in glob.glob(os.path.join(run, f"*-m{m}", "curves.csv")):
        with open(path, newline="", encoding="utf-8") as fh:
            for r in csv.DictReader(fh):
                key = (r["eval_model"], label(r))
                acc[key][(r["scenario"], r["seed"])][int(r["k"])] = float(r["risk"])
    out = {}
    for key, curves in acc.items():
        per_net = defaultdict(list)
        for (scen, _seed), pts in curves.items():
            r0 = pts[0]
            per_net[scen].append([pts[k] / r0 if r0 > 0 else 0.0 for k in sorted(pts)])
        nets = [[statistics.fmean(c[k] for c in cs) for k in range(len(cs[0]))]
                for cs in per_net.values()]
        out[key] = [statistics.fmean(n[k] for n in nets) for k in range(len(nets[0]))]
    return out


def figure(run, eval_model, ms, path):
    fig, axes = plt.subplots(1, len(ms), figsize=(3.0 * len(ms), 2.9), sharey=True)
    for ax, m in zip(axes, ms):
        curves = mean_curves(run, m)
        for pol, name, colour, marker in SERIES:
            ys = curves.get((eval_model, pol))
            if ys is None:
                continue
            ax.plot(range(len(ys)), ys, color=colour, lw=1.6, marker=marker, ms=4.5,
                    ls="--" if marker is None else "-", label=name, zorder=3)
        ax.set_title(f"m = {m}", color=TEXT, fontsize=10)
        ax.set_xlabel("số lần vá k", color=MUTED, fontsize=9)
        ax.set_ylim(-0.03, 1.05)
        ax.grid(True, color=GRID, lw=0.6, zorder=0)
        for side in ("top", "right"):
            ax.spines[side].set_visible(False)
        for side in ("left", "bottom"):
            ax.spines[side].set_color(GRID)
        ax.tick_params(colors=MUTED, labelsize=8)
    axes[0].set_ylabel("rủi ro còn lại R(k)/R(0)", color=MUTED, fontsize=9)
    handles, labels = axes[0].get_legend_handles_labels()
    fig.legend(handles, labels, loc="lower center", ncol=len(labels), frameon=False,
               fontsize=8, bbox_to_anchor=(0.5, -0.02))
    fig.suptitle(f"Nhóm V, chấm bằng {EVAL_NAME[eval_model]} (trung bình 40 mạng mỗi m)",
                 color=TEXT, fontsize=11)
    fig.tight_layout(rect=(0, 0.08, 1, 0.95))
    for ext in ("png", "pdf"):
        fig.savefig(f"{path}.{ext}", dpi=200, facecolor="#fcfcfb")
    plt.close(fig)


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("run", help="result directory, e.g. out/policies/V")
    ap.add_argument("--out", default="reports/figures")
    ap.add_argument("--m", default="1,2,3,5")
    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)
    ms = [int(x) for x in args.m.split(",")]
    name = os.path.basename(os.path.normpath(args.run))
    for ev in ("epss", "kev", "cvss"):
        figure(args.run, ev, ms, os.path.join(args.out, f"{name}_Rk_{ev}"))
        print(f"wrote {args.out}/{name}_Rk_{ev}.png/.pdf")


if __name__ == "__main__":
    main()
