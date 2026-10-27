"""Statistics over patch-policy results (ThietKe_ThiNghiem §7).

Input: one or more `summary.csv` files from `aapef.experiment`. One network =
one `scenario` id (group V: one structure x one CVE-assignment seed).

Per (eval model, policy, policy model):
    networks, mean AUC with a 95% bootstrap CI over networks, mean k_block
    (unblocked counted as K + 1), share of networks blocked within K.
The random policy is first averaged over its seeds within each network, so
every policy contributes one value per network.

Per pair of policies (same eval model, same networks):
    win rate (share of networks with strictly lower AUC; ties are reported),
    Wilcoxon signed-rank test on the AUC differences (exact for n <= 25 after
    dropping zero differences, normal approximation above), and the
    matched-pairs rank-biserial correlation as effect size.

    python -m aapef.policy_stats out/policies/run1/summary.csv [--out DIR]

Group N has too few networks for tests (ThietKe_ThiNghiem §7): the tables
are printed per scenario there and the test columns should not be read.
"""

import argparse
import csv
import itertools
import math
import os
import random
import statistics
from collections import defaultdict


def load_rows(paths):
    rows = []
    for p in paths:
        with open(p, newline="", encoding="utf-8") as fh:
            rows += list(csv.DictReader(fh))
    return rows


def per_network(rows):
    """{(eval_model, policy label): {network: (auc, k_block or None)}}."""
    acc = defaultdict(lambda: defaultdict(list))
    for r in rows:
        label = r["policy"] + (f"({r['policy_model']})" if r["policy_model"]
                               and r["policy"] != "optimal" else "")
        kb = int(r["k_block"]) if r["k_block"] != "" else None
        acc[(r["eval_model"], label)][r["scenario"]].append((float(r["auc"]), kb))
    out = {}
    for key, nets in acc.items():
        out[key] = {}
        for net, vals in nets.items():
            # random: several seeds -> mean AUC; k_block kept per seed list
            out[key][net] = (statistics.fmean(v[0] for v in vals), [v[1] for v in vals])
    return out


def bootstrap_ci(values, n_boot=2000, seed=0, level=0.95):
    """Percentile bootstrap CI of the mean."""
    if len(values) < 2:
        return (values[0], values[0]) if values else (None, None)
    rng = random.Random(seed)
    means = sorted(statistics.fmean(rng.choices(values, k=len(values)))
                   for _ in range(n_boot))
    lo = means[int((1 - level) / 2 * n_boot)]
    hi = means[int((1 + level) / 2 * n_boot) - 1]
    return lo, hi


def _ranks(abs_values):
    """Average ranks (1-based) with ties."""
    order = sorted(range(len(abs_values)), key=lambda i: abs_values[i])
    ranks = [0.0] * len(abs_values)
    i = 0
    while i < len(order):
        j = i
        while j + 1 < len(order) and abs_values[order[j + 1]] == abs_values[order[i]]:
            j += 1
        for t in range(i, j + 1):
            ranks[order[t]] = (i + j) / 2 + 1
        i = j + 1
    return ranks


def wilcoxon(diffs, exact_max=25):
    """(W+, two-sided p, rank-biserial r, n used) for paired differences.

    Zero differences are dropped (Wilcoxon's convention). Exact p by
    enumerating sign patterns of the (possibly tied) ranks when n <= exact_max,
    else the normal approximation with tie correction.
    """
    d = [x for x in diffs if x != 0]
    n = len(d)
    if n == 0:
        return 0.0, 1.0, 0.0, 0
    ranks = _ranks([abs(x) for x in d])
    w_plus = sum(r for r, x in zip(ranks, d) if x > 0)
    total = n * (n + 1) / 2
    r_rb = (2 * w_plus - total) / total     # +1: all differences positive
    if n <= exact_max:
        # distribution of W+ over 2^n sign patterns, by dynamic programming on
        # doubled ranks (ranks may be halves when tied)
        dist = {0: 1}
        for rk in ranks:
            step = int(round(2 * rk))
            nxt = defaultdict(int)
            for s, c in dist.items():
                nxt[s] += c
                nxt[s + step] += c
            dist = nxt
        obs = int(round(2 * w_plus))
        mean2 = int(round(total))   # E[2W+] = total
        dev = abs(obs - mean2)
        extreme = sum(c for s, c in dist.items() if abs(s - mean2) >= dev)
        p = min(1.0, extreme / 2 ** n)
    else:
        ties = defaultdict(int)
        for rk in ranks:
            ties[rk] += 1
        var = n * (n + 1) * (2 * n + 1) / 24 - sum(t ** 3 - t for t in ties.values()) / 48
        z = (w_plus - total / 2) / math.sqrt(var) if var > 0 else 0.0
        p = math.erfc(abs(z) / math.sqrt(2))
    return w_plus, p, r_rb, n


def policy_table(data, k_max):
    out = []
    for (ev, label), nets in sorted(data.items()):
        aucs = [v[0] for v in nets.values()]
        kbs = [kb for v in nets.values() for kb in v[1]]
        lo, hi = bootstrap_ci(aucs)
        out.append({"eval_model": ev, "policy": label, "networks": len(nets),
                    "mean_auc": statistics.fmean(aucs), "ci_low": lo, "ci_high": hi,
                    "mean_k_block": statistics.fmean(k_max + 1 if kb is None else kb
                                                     for kb in kbs),
                    "blocked_share": sum(kb is not None for kb in kbs) / len(kbs)})
    return out


def pair_table(data):
    out = []
    evals = sorted({ev for ev, _ in data})
    for ev in evals:
        labels = sorted(lbl for e, lbl in data if e == ev)
        for a, b in itertools.combinations(labels, 2):
            nets = sorted(set(data[(ev, a)]) & set(data[(ev, b)]))
            if not nets:
                continue
            diffs = [data[(ev, a)][n][0] - data[(ev, b)][n][0] for n in nets]
            w, p, r, used = wilcoxon(diffs)
            out.append({"eval_model": ev, "a": a, "b": b, "networks": len(nets),
                        "a_wins": sum(x < 0 for x in diffs), "b_wins": sum(x > 0 for x in diffs),
                        "ties": sum(x == 0 for x in diffs),
                        "mean_diff_auc": statistics.fmean(diffs),
                        "wilcoxon_w_plus": w, "p_value": p, "rank_biserial": r,
                        "n_nonzero": used})
    return out


def _write(path, rows):
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, list(rows[0]))
        w.writeheader()
        w.writerows(rows)


def _fmt(v):
    return f"{v:.3f}" if isinstance(v, float) else str(v)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("summaries", nargs="+")
    ap.add_argument("--K", type=int, default=6, help="K of the runs (for unblocked k_block)")
    ap.add_argument("--out", default=None, help="directory for policies.csv and pairs.csv")
    args = ap.parse_args(argv)
    data = per_network(load_rows(args.summaries))
    pol, pairs = policy_table(data, args.K), pair_table(data)
    for title, rows in (("policies", pol), ("pairs", pairs)):
        print(f"== {title}")
        if rows:
            print("  " + " | ".join(rows[0]))
            for r in rows:
                print("  " + " | ".join(_fmt(v) for v in r.values()))
    if args.out:
        os.makedirs(args.out, exist_ok=True)
        _write(os.path.join(args.out, "policies.csv"), pol)
        if pairs:
            _write(os.path.join(args.out, "pairs.csv"), pairs)


if __name__ == "__main__":
    main()
