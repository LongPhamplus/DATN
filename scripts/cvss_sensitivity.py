"""Sensitivity of the main findings to the published CVSS cost-model assumptions.

For each assumption variant (plan §9.3: scale, p normalisation, information-
gathering probability, default AC / UI) every scenario in the config is
re-costed from its ORIGINAL file and solved by all five algorithms. The
question per variant: do the headline findings survive?

    tradeoff        BFS path is shorter than Dijkstra's AND costlier than C*
    astar_optimal   A* cost equals the Dijkstra cost C*
    dijkstra_min    C* is not above any other algorithm's path cost

Usage (from the repo root):
    python scripts/cvss_sensitivity.py --config scenarios/benchmark_cvss.json \
        --out out/cvss/assumption_sensitivity.csv
"""

import argparse
import csv
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir))

from aapef.benchmark import search_once  # noqa: E402
from aapef.cvss import CostModel, recost_scenario  # noqa: E402
from aapef.scenario import build_scenario  # noqa: E402
from aapef.simulate import path_cost  # noqa: E402

VARIANTS = {
    "default": {},
    "scale_100": {"scale": 100},
    "p_norm_3.9": {"p_norm": 3.9},
    "discovery_p_0.5": {"discovery_p": 0.5},
    "discovery_p_0.99": {"discovery_p": 0.99},
    "default_ac_H": {"default_ac": "H"},
    "default_ui_R": {"default_ui": "R"},
}
ALGOS = ("bfs", "dfs", "dijkstra", "greedy", "astar")
FIELDS = ("variant", "scenario_id", "c_star", "bfs_cost", "dfs_cost",
          "greedy_cost", "astar_cost", "bfs_len", "dijkstra_len",
          "tradeoff", "astar_optimal", "dijkstra_min")


def evaluate(variant, params, scenario_id, scen_dir):
    path = os.path.join(scen_dir, f"{scenario_id}.json")
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    scenario = build_scenario(recost_scenario(data, CostModel(**params)))
    found = {a: search_once(scenario, a)[0] for a in ALGOS}
    if found["dijkstra"] is None or not found["dijkstra"]:
        return None  # no path, or goal already satisfied: nothing to compare
    cost = {a: path_cost(p, scenario) for a, p in found.items()}
    c_star = cost["dijkstra"]
    return {
        "variant": variant, "scenario_id": scenario_id, "c_star": c_star,
        "bfs_cost": cost["bfs"], "dfs_cost": cost["dfs"],
        "greedy_cost": cost["greedy"], "astar_cost": cost["astar"],
        "bfs_len": len(found["bfs"]), "dijkstra_len": len(found["dijkstra"]),
        "tradeoff": len(found["bfs"]) < len(found["dijkstra"]) and cost["bfs"] > c_star,
        "astar_optimal": cost["astar"] == c_star,
        "dijkstra_min": all(c_star <= c for c in cost.values()),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--config", default="scenarios/benchmark_cvss.json")
    parser.add_argument("--scenarios-dir", default="scenarios")
    parser.add_argument("--out", default="out/cvss/assumption_sensitivity.csv")
    args = parser.parse_args()

    with open(args.config, "r", encoding="utf-8") as fh:
        ids = json.load(fh)["scenarios"]

    rows = []
    for variant, params in VARIANTS.items():
        for sid in ids:
            row = evaluate(variant, params, sid, args.scenarios_dir)
            if row is not None:
                rows.append(row)

    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    with open(args.out, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(rows)

    print(f"{'variant':<18} {'scen':>4} {'tradeoff':>8} {'astar=C*':>9} {'dij_min':>8}")
    for variant in VARIANTS:
        sel = [r for r in rows if r["variant"] == variant]
        print(f"{variant:<18} {len(sel):>4} "
              f"{sum(r['tradeoff'] for r in sel):>8} "
              f"{sum(r['astar_optimal'] for r in sel):>9} "
              f"{sum(r['dijkstra_min'] for r in sel):>8}")
    print(f"wrote {os.path.abspath(args.out)}")


if __name__ == "__main__":
    main()
