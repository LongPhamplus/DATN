"""Benchmark AAPEF on scenarios from NASim's generator (report BaoCao_Benchmark_NASimGen).

Three variants of every generated network:

    plain   scenarios/G/<net>.json          costs from NASim (cost / prob), no CVE
    cve-m1  scenarios/G_cve/<net>-m1-s0.json   1 real CVE per vulnerability slot
    cve-m3  scenarios/G_cve/<net>-m3-s0.json   3 real CVEs per slot

Jobs, each in its own process with a wall-clock limit and an address-space
limit, so one network that does not fit cannot stop the run:

    space   full reachable state space, stopped at --space-cap states
    search  one of the 5 algorithms (BFS, DFS, Dijkstra, Greedy, A*) to the
            scenario goal; CVE variants use integer costs round(10 * -ln p)
            with p from the CVSS model of the snapshot (as `aapef recost`)
    policy  (CVE variants) risk oracle under the CVSS model: R(0), the
            context-greedy order for K = 6, the score policies, 20 random
            orders and, when units <= 14, the exhaustive optimum; R(k) curves

Peak memory is the tracemalloc peak (Python objects allocated by the job) and
the process max RSS; runtime is measured in a separate run without tracemalloc.

    python scripts/bench_nasim_gen.py --out out/nasim_gen [--workers 3]

Writes space.csv, search.csv, policy.csv, curves.csv.
"""

import argparse
import csv
import glob
import json
import math
import os
import resource
import statistics
import subprocess
import sys
import tracemalloc
from concurrent.futures import ThreadPoolExecutor
from time import perf_counter

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

HERE = os.path.abspath(__file__)
ALGS = ("bfs", "dfs", "dijkstra", "greedy", "astar")
K = 6
RANDOM_SEEDS = 20


# ---------------------------------------------------------------- one job --

def _load(path, variant, snap):
    from aapef.scenario import build_scenario
    from aapef.prob import ProbModel, cost_table
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    if variant != "plain":
        costs = cost_table(data, ProbModel("cvss"), snap)
        data = dict(data, actions=[{**a, "cost": max(1, round(10 * costs[a["id"]]))}
                                   for a in data["actions"]])
    return data, build_scenario(data)


def _traced(fn):
    tracemalloc.start()
    out = fn()
    peak = tracemalloc.get_traced_memory()[1]
    tracemalloc.stop()
    return out, round(peak / 1024, 1)


def _timed(fn, budget_s=2.0, repeats=3):
    samples = []
    while len(samples) < repeats:
        t0 = perf_counter()
        fn()
        samples.append((perf_counter() - t0) * 1000)
        if sum(samples) > budget_s * 1000:
            break
    return round(statistics.median(samples), 2)


def job_space(sc, cap):
    from aapef.state import initial_state, state_key, successors

    def run():
        start = initial_state(sc)
        seen = {state_key(start)}
        edges, stack = 0, [start]
        while stack and len(seen) < cap:
            for _a, nxt, _c in successors(stack.pop(), sc):
                edges += 1
                k = state_key(nxt)
                if k not in seen:
                    seen.add(k)
                    stack.append(nxt)
        return len(seen), edges, bool(stack)
    t0 = perf_counter()
    (states, edges, capped), kib = _traced(run)
    return {"states": states, "edges": edges, "capped": capped, "peak_kib": kib,
            "traced_ms": round((perf_counter() - t0) * 1000, 1)}


def job_search(sc, alg):
    from aapef.benchmark import search_once
    (path, met), kib = _traced(lambda: search_once(sc, alg))
    cost = None
    if path is not None:
        by_id = {a.id: a.cost for a in sc.actions}
        cost = sum(by_id[a] for a in path)
    return {"found": path is not None, "path_len": None if path is None else len(path),
            "path_cost": cost, "nodes_expanded": met["nodes_expanded"],
            "edges_examined": met["edges_examined"], "peak_kib": kib,
            "runtime_ms": _timed(lambda: search_once(sc, alg))}


def job_policy(data, snap):
    from aapef import policies as P
    from aapef.defense import (RiskOracle, curve_metrics, patch_units, risk_curve,
                               scenario_for_risk, sensitive_hosts)
    from aapef.experiment import SCORE_POLICIES
    from aapef.prob import ProbModel, cost_table

    t0 = perf_counter()
    units = patch_units(data)
    costs = cost_table(data, ProbModel("cvss"), snap)
    oracle = RiskOracle(scenario_for_risk(data), costs, units, sensitive_hosts(data))
    setup_ms = (perf_counter() - t0) * 1000
    out = {"units": len(units), "targets": len(oracle.goals), "setup_ms": round(setup_ms, 1)}

    t0 = perf_counter()
    r0, path0 = oracle.evaluate([])
    out.update(r0=r0, best_path_len=len(path0 or []), r0_searches=oracle.searches,
               r0_ms=round((perf_counter() - t0) * 1000, 1))

    def greedy():
        o = RiskOracle(oracle.scenario, costs, units, sensitive_hosts(data))
        return o, P.context_greedy(o, K)
    t0 = perf_counter()
    (o, ctx), kib = _traced(greedy)
    out.update(ctx_searches=o.searches, ctx_peak_kib=kib)
    t0 = perf_counter()
    greedy()
    out["ctx_ms"] = round((perf_counter() - t0) * 1000, 1)

    orders = {"context-greedy": ctx}
    t0 = perf_counter()
    for name, fn in SCORE_POLICIES.items():
        orders[name] = fn(data, units, snap)
    out["score_ms"] = round((perf_counter() - t0) * 1000, 2)

    curves = {}
    for name, order in orders.items():
        curves[name] = risk_curve(oracle, order, K)
    rnd = [risk_curve(oracle, P.random_order(units, s), K) for s in range(RANDOM_SEEDS)]
    curves["random"] = [statistics.mean(c[k] for c in rnd) for k in range(K + 1)]
    out["optimal"] = len(units) <= 14
    if out["optimal"]:
        o = RiskOracle(oracle.scenario, costs, units, sensitive_hosts(data))
        t0 = perf_counter()
        opt = P.optimal(o, K)
        out.update(opt_searches=o.searches, opt_ms=round((perf_counter() - t0) * 1000, 1))
        curves["optimal"] = [r for r, _ in opt]
    out["curves"] = {n: {"curve": c, **curve_metrics(c)} for n, c in curves.items()}
    out["eval_searches_total"] = oracle.searches
    return out


def child(spec):
    limit = spec["mem_gb"] * 1024 ** 3
    resource.setrlimit(resource.RLIMIT_AS, (limit, limit))
    snap = None
    if spec["variant"] != "plain":
        from aapef.data import load_snapshot
        snap = load_snapshot(spec["snapshot"])
    try:
        data, sc = _load(spec["path"], spec["variant"], snap)
        if spec["kind"] == "space":
            row = job_space(sc, spec["cap"])
        elif spec["kind"] == "search":
            row = job_search(sc, spec["alg"])
        else:
            row = job_policy(data, snap)
        row["status"] = "ok"
    except MemoryError:
        row = {"status": "oom"}
    row["maxrss_mib"] = round(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024, 1)
    print(json.dumps(row))


# ------------------------------------------------------------------ driver --

def describe(path):
    with open(path, encoding="utf-8") as fh:
        d = json.load(fh)
    real = [h for h in d["hosts"] if h["id"] not in ("ATK", "GOAL")]
    return {"hosts": len(real), "actions": len(d["actions"])}


def run(spec, timeout):
    t0 = perf_counter()
    try:
        p = subprocess.run([sys.executable, HERE, "--child", json.dumps(spec)],
                           capture_output=True, text=True, timeout=timeout)
        lines = [ln for ln in p.stdout.splitlines() if ln.startswith("{")]
        row = json.loads(lines[-1]) if lines else {"status": f"error rc={p.returncode}",
                                                   "stderr": p.stderr[-300:]}
    except subprocess.TimeoutExpired:
        row = {"status": "timeout"}
    row["wall_s"] = round(perf_counter() - t0, 1)
    return row


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--child")
    ap.add_argument("--out", default="out/nasim_gen")
    ap.add_argument("--snapshot", default="data/snapshots")
    ap.add_argument("--workers", type=int, default=3)
    ap.add_argument("--timeout", type=int, default=300, help="seconds per job")
    ap.add_argument("--mem-gb", type=int, default=4, help="address-space limit per job")
    ap.add_argument("--space-cap", type=int, default=1_000_000)
    ap.add_argument("--only", default="", help="substring filter on network names")
    args = ap.parse_args()
    if args.child:
        child(json.loads(args.child))
        return

    nets = sorted(os.path.basename(p)[:-5] for p in glob.glob("scenarios/G/*.json"))
    nets = [n for n in nets if args.only in n]
    variants = [("plain", "scenarios/G/{n}.json"), ("cve-m1", "scenarios/G_cve/{n}-m1-s0.json"),
                ("cve-m3", "scenarios/G_cve/{n}-m3-s0.json")]
    specs = []
    for n in nets:
        for v, pat in variants:
            base = {"network": n, "family": n.rsplit("-s", 1)[0], "variant": v,
                    "path": pat.format(n=n), "snapshot": args.snapshot, "mem_gb": args.mem_gb}
            specs.append({**base, "kind": "space", "cap": args.space_cap})
            specs += [{**base, "kind": "search", "alg": a} for a in ALGS]
            if v != "plain":
                specs.append({**base, "kind": "policy"})

    os.makedirs(args.out, exist_ok=True)
    rows = []

    def one(spec):
        row = {**{k: spec[k] for k in ("network", "family", "variant", "kind")},
               "algorithm": spec.get("alg", ""), **describe(spec["path"]),
               **run(spec, args.timeout)}
        print(f"{row['network']:16} {row['variant']:6} {row['kind']:6} {row['algorithm']:8} "
              f"{row['status']:8} {row['wall_s']:7.1f}s", flush=True)
        return row
    with ThreadPoolExecutor(args.workers) as ex:
        rows = list(ex.map(one, specs))

    with open(os.path.join(args.out, "raw.json"), "w", encoding="utf-8") as fh:
        json.dump(rows, fh, indent=1)
    write_csvs(rows, args.out)


def write_csvs(rows, out):
    def dump(name, sel, drop=()):
        sel = [{k: v for k, v in r.items() if k not in drop} for r in sel]
        if not sel:
            return
        keys = []
        for r in sel:
            keys += [k for k in r if k not in keys]
        with open(os.path.join(out, name), "w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=keys)
            w.writeheader()
            w.writerows(sel)
    dump("space.csv", [r for r in rows if r["kind"] == "space"], ("algorithm",))
    dump("search.csv", [r for r in rows if r["kind"] == "search"])
    pol = [r for r in rows if r["kind"] == "policy"]
    dump("policy.csv", pol, ("algorithm", "curves"))
    curves = []
    for r in pol:
        for name, c in (r.get("curves") or {}).items():
            curves.append({"network": r["network"], "family": r["family"], "variant": r["variant"],
                           "policy": name, "auc": c["auc"], "k_block": c.get("k_block"),
                           **{f"R{k}": v for k, v in enumerate(c["curve"])}})
    dump("curves.csv", curves)


if __name__ == "__main__":
    main()
