"""Patch-policy experiment runner (ThietKe_ThiNghiem §3-§5, KeHoachPhatTrien 4.2).

For every scenario, every policy builds a patch order using the model it is
allowed to see (`policy model`), and the order is then scored under every
evaluation model (cross-evaluation, ThietKe_ThiNghiem §6). Risk is that of
reaching any sensitive host (decision of 2026-10-27).

    python -m aapef.experiment scenarios/small.json ... --models cvss \
        --out out/policies/run1 [--snapshot data/snapshots] [--K 6]

Writes into --out:
    curves.csv   one row per (scenario, policy, policy model, eval model, seed, k)
    summary.csv  one row per curve: R(0), AUC, k_block, patch order
    meta.json    parameters, model descriptions, snapshot id, timing
"""

import argparse
import csv
import json
import math
import os
import time

from . import policies as P
from .data import load_snapshot
from .defense import (
    RiskOracle, curve_metrics, patch_units, risk_curve, scenario_for_risk,
    sensitive_hosts,
)
from .prob import ProbModel, cost_table

SCORE_POLICIES = {"cvss-base": P.cvss_base, "cvss-exploit": P.cvss_exploit,
                  "epss": P.epss, "kev-first": P.kev_first}


def _all_cve_units(units):
    return all("@" in u and u.startswith("CVE-") for u in units)


def run_scenario(data, models, k_max, seeds, snapshot=None, max_optimal_units=14):
    """Yield (row dict, order) for every curve of one scenario."""
    sc = scenario_for_risk(data)
    units = patch_units(data)
    targets = sensitive_hosts(data)
    oracles = {m.name: RiskOracle(sc, cost_table(data, m, snapshot), units, targets)
               for m in models}
    orders = []   # (policy, policy model or "", seed or "", order)
    for m in models:
        orders.append(("context-greedy", m.name, "", P.context_greedy(oracles[m.name], k_max)))
        orders.append(("by-probability", m.name, "",
                       P.by_probability(data, units, m, snapshot)))
    for s in seeds:
        orders.append(("random", "", s, P.random_order(units, s)))
    if snapshot is not None and _all_cve_units(units):
        for name, fn in SCORE_POLICIES.items():
            orders.append((name, "", "", fn(data, units, snapshot)))
    for ev in models:
        oracle = oracles[ev.name]
        for policy, pmodel, seed, order in orders:
            yield {"policy": policy, "policy_model": pmodel, "eval_model": ev.name,
                   "seed": seed}, risk_curve(oracle, order, k_max), order[:k_max]
        if len(units) <= max_optimal_units:
            opt = P.optimal(oracle, k_max)
            yield ({"policy": "optimal", "policy_model": ev.name, "eval_model": ev.name,
                    "seed": ""}, [r for r, _ in opt], opt[-1][1])


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("scenarios", nargs="+")
    ap.add_argument("--models", default="cvss",
                    help="comma list of probability models (cvss,epss,kev,native)")
    ap.add_argument("--K", type=int, default=6)
    ap.add_argument("--seeds", type=int, default=200, help="random-policy seeds 0..N-1")
    ap.add_argument("--p-kev", type=float, default=ProbModel("kev").p_kev)
    ap.add_argument("--snapshot", default=None, help="snapshot directory (needed for cve)")
    ap.add_argument("--snapshot-name", default=None)
    ap.add_argument("--max-optimal-units", type=int, default=14)
    ap.add_argument("--out", required=True)
    args = ap.parse_args(argv)

    models = [ProbModel(n.strip(), p_kev=args.p_kev) for n in args.models.split(",")]
    for m in models:
        m.validate()
    snap = load_snapshot(args.snapshot, args.snapshot_name) if args.snapshot else None
    os.makedirs(args.out, exist_ok=True)
    t0 = time.time()
    curve_rows, summary_rows, timing = [], [], {}
    for path in args.scenarios:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        sid = data["scenario_id"]
        ts = time.time()
        for key, curve, order in run_scenario(data, models, args.K, range(args.seeds),
                                              snap, args.max_optimal_units):
            base = {"scenario": sid, **key}
            for k, r in enumerate(curve):
                curve_rows.append({**base, "k": k, "risk": r,
                                   "log10_risk": math.log10(r) if r > 0 else ""})
            met = curve_metrics(curve)
            summary_rows.append({**base, "r0": curve[0], "auc": met["auc"],
                                 "k_block": "" if met["k_block"] is None else met["k_block"],
                                 "order": " ".join(order)})
        timing[sid] = round(time.time() - ts, 2)
        print(f"{sid}: {timing[sid]}s", flush=True)

    snap_id = snap.id if snap else ""
    for name, rows in (("curves.csv", curve_rows), ("summary.csv", summary_rows)):
        with open(os.path.join(args.out, name), "w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, ["snapshot_id"] + list(rows[0]))
            w.writeheader()
            for r in rows:
                w.writerow({"snapshot_id": snap_id, **r})
    meta = {"scenarios": args.scenarios, "K": args.K, "seeds": args.seeds,
            "models": [m.describe() for m in models], "snapshot_id": snap_id,
            "risk": "any sensitive host (max over targets)",
            "max_optimal_units": args.max_optimal_units,
            "seconds": round(time.time() - t0, 2), "seconds_per_scenario": timing}
    with open(os.path.join(args.out, "meta.json"), "w", encoding="utf-8") as fh:
        json.dump(meta, fh, indent=2)
        fh.write("\n")


if __name__ == "__main__":
    main()
