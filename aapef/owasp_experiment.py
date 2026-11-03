"""Patch / block policies compared under the OWASP risk model (RQ1-RQ3).

For every scenario and organisation profile, R(k) = sum over assets of
likelihood x impact after the first k measures of each policy's order:

  patch measures (RQ1, RQ2)
    context-greedy   owasp.greedy on CVE@host units (sees the attack graph)
    owasp-vuln       OWASP rating of each vulnerability on its own host
    cvss-base, cvss-exploit, epss, kev-first     score policies (policies.py)
    random           20 seeds
    optimal          exhaustive, when units <= --max-optimal-units
  firewall (RQ3)
    context-block    owasp.greedy on block units only
    context-combined owasp.greedy on patch + block units

Profiles (organisation settings, RQ2 sensitivity):
    default            config defaults (owasp.DEFAULT_CONFIG)
    monitored-assets   intrusion detection 3 ("logged and reviewed") in the
                       zones that hold an asset
    open-internal      no business flows: Internet flows can be blocked too

Writes, in --out:
    summary.csv  the columns of aapef.experiment (so aapef.policy_stats reads
                 it; eval_model = owasp:<profile>, auc and k_block over R(k)/R(0))
                 plus k_accept: first k at which every asset is at or below
                 the acceptance level (empty if not within K)
    curves.csv   R(k) / R(0) for k = 0..K
    networks.csv size, units, assets, R(0), levels, time per scenario

    python -m aapef.owasp_experiment scenarios/V/*.json --snapshot data/snapshots \
        --K 10 --out out/owasp/V
"""

import argparse
import csv
import json
import os
import statistics
import time

from . import owasp as O
from . import policies as P
from .defense import curve_metrics, patch_units
from .experiment import SCORE_POLICIES

PROFILES = ("default", "monitored-assets", "open-internal")
RANDOM_SEEDS = 20


def profile_config(name, data):
    if name == "default":
        return O.make_config()
    if name == "monitored-assets":
        cfg = O.make_config()
        zones = {O.zone_of(h, cfg) for h in O.asset_hosts(data, cfg)}
        return O.make_config({"intrusion_detection": {"zones": {z: 3 for z in zones}}})
    if name == "open-internal":
        return O.make_config({"business_flows": []})
    raise ValueError(f"unknown profile {name!r}; use one of {PROFILES}")


def _curve(oracle, order, k_max):
    return [oracle(order[:k]) for k in range(k_max + 1)]


def _k_accept(oracle, order, k_max):
    for k in range(min(k_max, len(order)) + 1):
        if oracle.accepted(order[:k]):
            return k
    return None


def run_scenario(data, snapshot, profile, k_max, max_optimal_units=14, block=True):
    """Yield (row, curve) per policy, and one network-description dict last."""
    cfg = profile_config(profile, data)
    t0 = time.perf_counter()
    op = O.OwaspOracle(data, cfg, snapshot, ("patch",))
    units = op.unit_actions
    orders = [("context-greedy", op, O.greedy(op, k_max)),
              ("owasp-vuln", op, O.per_vulnerability(data, units, cfg, snapshot))]
    for name, fn in SCORE_POLICIES.items():
        orders.append((name, op, fn(data, patch_units(data), snapshot)))
    rows = []
    for name, oracle, order in orders:
        rows.append((name, "", oracle, order))
    for s in range(RANDOM_SEEDS):
        rows.append(("random", s, op, P.random_order(units, s)))
    if block:
        ob = O.OwaspOracle(data, cfg, snapshot, ("block",))
        oc = O.OwaspOracle(data, cfg, snapshot, ("patch", "block"))
        rows.append(("context-block", "", ob, O.greedy(ob, k_max)))
        rows.append(("context-combined", "", oc, O.greedy(oc, k_max)))
    ev = f"owasp:{profile}"
    for name, seed, oracle, order in rows:
        curve = _curve(oracle, order, k_max)
        m = curve_metrics(curve)
        yield ({"scenario": data["scenario_id"], "policy": name, "policy_model": "",
                "eval_model": ev, "seed": seed, "r0": curve[0], "auc": m["auc"],
                "k_block": m["k_block"], "k_accept": _k_accept(oracle, order, k_max),
                "order": " ".join(order[:k_max])}, curve)
    if len(units) <= max_optimal_units:
        opt = P.optimal(op, k_max)
        curve = [r for r, _ in opt]
        m = curve_metrics(curve)
        ka = next((k for k, (_, s) in enumerate(opt) if op.accepted(s)), None)
        yield ({"scenario": data["scenario_id"], "policy": "optimal", "policy_model": "",
                "eval_model": ev, "seed": "", "r0": curve[0], "auc": m["auc"],
                "k_block": m["k_block"], "k_accept": ka,
                "order": " ".join(opt[-1][1])}, curve)
    before = op.assess([])
    yield {"scenario": data["scenario_id"], "profile": profile,
           "hosts": len([h for h in data["hosts"] if h["id"] not in ("ATK", "GOAL")]),
           "actions": len(data["actions"]), "patch_units": len(units),
           "block_units": len(O.block_units(data, cfg)) if block else "",
           "assets": " ".join(op.assets), "r0": op([]),
           "levels": " ".join(f"{h}:{r['level']}" for h, r in before.items()),
           "seconds": round(time.perf_counter() - t0, 3)}


SUMMARY = ["snapshot_id", "scenario", "policy", "policy_model", "eval_model", "seed", "r0",
           "auc", "k_block", "k_accept", "order"]


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("scenarios", nargs="+")
    ap.add_argument("--snapshot", default="data/snapshots")
    ap.add_argument("--snapshot-name", default=None)
    ap.add_argument("--profiles", default="default")
    ap.add_argument("--K", type=int, default=10)
    ap.add_argument("--max-optimal-units", type=int, default=14)
    ap.add_argument("--no-block", action="store_true")
    ap.add_argument("--out", required=True)
    args = ap.parse_args(argv)
    from .data import load_snapshot
    snap = load_snapshot(args.snapshot, args.snapshot_name)
    os.makedirs(args.out, exist_ok=True)
    fs = open(os.path.join(args.out, "summary.csv"), "w", newline="", encoding="utf-8")
    fc = open(os.path.join(args.out, "curves.csv"), "w", newline="", encoding="utf-8")
    fn = open(os.path.join(args.out, "networks.csv"), "w", newline="", encoding="utf-8")
    ws = csv.DictWriter(fs, fieldnames=SUMMARY)
    ws.writeheader()
    wc = csv.writer(fc)
    wc.writerow(["scenario", "eval_model", "policy", "seed"] + [f"R{k}" for k in range(args.K + 1)])
    wn = None
    for path in args.scenarios:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        for profile in args.profiles.split(","):
            for item in run_scenario(data, snap, profile, args.K, args.max_optimal_units,
                                     not args.no_block):
                if isinstance(item, dict):
                    if wn is None:
                        wn = csv.DictWriter(fn, fieldnames=list(item))
                        wn.writeheader()
                    wn.writerow(item)
                    print(f"{item['scenario']:45} {profile:16} units {item['patch_units']:4} "
                          f"R0 {item['r0']:7.2f} {item['seconds']:7.2f}s", flush=True)
                    continue
                row, curve = item
                ws.writerow({**row, "snapshot_id": snap.id})
                r0 = curve[0]
                wc.writerow([row["scenario"], row["eval_model"], row["policy"], row["seed"]]
                            + [round(c / r0, 6) if r0 else 0.0 for c in curve])
    for f in (fs, fc, fn):
        f.close()


if __name__ == "__main__":
    main()
