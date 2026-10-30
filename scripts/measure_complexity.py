"""Measured search effort, runtime and peak memory (progress report, 2026-10-30).

Part 1 (v1): every algorithm on the size ladders of scenarios/cvss/. Peak
memory is the tracemalloc peak of one search run (Python objects allocated
during the run: frontier, visited set, stored paths), in KiB. Runtime is the
median of 5 runs without tracemalloc, which slows allocation.

Part 2 (v2): the risk oracle of the patch-policy experiment on one group-V
network per structure (m = 1 and m = 5, seed 0, model cvss): number of A*
searches, runtime and peak memory of the context-greedy policy (K = 6) and of
the exhaustive optimum.

    python scripts/measure_complexity.py --out out/complexity

Writes search.csv and policy.csv. Runtime depends on the machine; the counts
do not.
"""

import argparse
import csv
import json
import os
import statistics
import sys
import tracemalloc
from time import perf_counter

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from aapef import policies as P                                    # noqa: E402
from aapef.benchmark import measure_state_space, search_once       # noqa: E402
from aapef.data import load_snapshot                               # noqa: E402
from aapef.defense import (                                        # noqa: E402
    RiskOracle, patch_units, scenario_for_risk, sensitive_hosts)
from aapef.prob import ProbModel, cost_table                       # noqa: E402
from aapef.scenario import load_scenario                           # noqa: E402
from aapef.search import ALGORITHMS                                # noqa: E402

LADDERS = ["size-v132", "size-v352", "size-v1026", "size-v3024", "size-v11264",
           "cve-size-v112", "cve-size-v336", "cve-size-v1024", "cve-size-v4032",
           "cve-size-v16128"]
STRUCTS = ["small", "small-linear", "medium-single-site", "medium-multi-site"]
REPEATS = 5


def peak_kib(fn):
    tracemalloc.start()
    out = fn()
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    return out, round(peak / 1024, 1)


def median_ms(fn, repeats=REPEATS):
    samples = []
    for _ in range(repeats):
        t0 = perf_counter()
        fn()
        samples.append((perf_counter() - t0) * 1000)
    return round(statistics.median(samples), 3)


def part1():
    rows = []
    for sid in LADDERS:
        sc = load_scenario(f"scenarios/cvss/{sid}.json")
        space, space_kib = peak_kib(lambda: measure_state_space(sc))
        for alg in ALGORITHMS:
            (path, met), kib = peak_kib(lambda: search_once(sc, alg))
            rows.append({"scenario": sid, "states": space["num_states"],
                         "edges": space["num_edges"], "full_space_kib": space_kib,
                         "algorithm": alg, "path_len": None if path is None else len(path),
                         "nodes_expanded": met["nodes_expanded"],
                         "edges_examined": met["edges_examined"],
                         "peak_kib": kib,
                         "runtime_ms": median_ms(lambda: search_once(sc, alg))})
        print(sid, flush=True)
    return rows


def part2(snap):
    model = ProbModel("cvss")
    rows = []
    for s in STRUCTS:
        for m in (1, 5):
            with open(f"scenarios/V/{s}-m{m}-s0.json", encoding="utf-8") as fh:
                data = json.load(fh)
            units = patch_units(data)
            costs = cost_table(data, model, snap)

            def oracle():
                return RiskOracle(scenario_for_risk(data), costs, units, sensitive_hosts(data))

            for policy in ("context-greedy", "optimal"):
                if policy == "optimal" and len(units) > 14:
                    continue
                run = ((lambda o: P.context_greedy(o, 6)) if policy == "context-greedy"
                       else (lambda o: P.optimal(o, 6)))
                o = oracle()
                _, kib = peak_kib(lambda: run(o))
                searches = o.searches
                t0 = perf_counter()
                run(oracle())
                ms = round((perf_counter() - t0) * 1000, 1)
                rows.append({"network": f"{s}-m{m}-s0", "hosts": len(data["hosts"]),
                             "actions": len(data["actions"]), "units": len(units),
                             "policy": policy, "K": 6, "astar_searches": searches,
                             "runtime_ms": ms, "peak_kib": kib})
            print(s, m, flush=True)
    return rows


def write(path, rows):
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", default="out/complexity")
    ap.add_argument("--snapshot", default="data/snapshots")
    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)
    write(os.path.join(args.out, "search.csv"), part1())
    write(os.path.join(args.out, "policy.csv"), part2(load_snapshot(args.snapshot)))


if __name__ == "__main__":
    main()
