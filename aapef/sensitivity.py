"""Action-order sensitivity experiment (plan §4.3, §10; RQ1/RQ2/RQ4).

The algorithms break ties by the order actions are declared in the scenario
file. This experiment re-runs each algorithm on several seeded permutations of
that order and reports how much the result moves. Expected by theory:

- BFS's path length and Dijkstra's path cost are the same for every order
  (optimality does not depend on tie-breaks), though the chosen path may differ.
- DFS (and possibly Greedy) can change length, cost and effort with the order.

Permutations come from `random.Random(f"{seed}:{scenario_id}")`, so results are
reproducible and each scenario's permutations do not depend on which other
scenarios are in the run. Order 0 is always the original file order.
"""

import csv
import dataclasses
import os
import random

from .benchmark import search_once
from .simulate import path_cost

SENSITIVITY_FIELDS = (
    "scenario_id", "algorithm", "orders", "found_count", "distinct_paths",
    "min_actions", "max_actions", "min_cost", "max_cost",
    "min_nodes", "max_nodes",
)


def permuted_orders(scenario, permutations, seed):
    """The original scenario followed by `permutations` reordered copies."""
    rng = random.Random(f"{seed}:{scenario.scenario_id}")
    variants = [scenario]
    for _ in range(permutations):
        actions = list(scenario.actions)
        rng.shuffle(actions)
        variants.append(dataclasses.replace(scenario, actions=actions))
    return variants


def _span(values):
    return (min(values), max(values)) if values else (None, None)


def order_sensitivity(scenario, algorithms, permutations=20, seed=42):
    """Return one summary row per algorithm over all action orders."""
    variants = permuted_orders(scenario, permutations, seed)
    rows = []
    for algorithm in algorithms:
        runs = [search_once(v, algorithm) for v in variants]
        paths = [p for p, _m in runs if p is not None]
        min_l, max_l = _span([len(p) for p in paths])
        min_c, max_c = _span([path_cost(p, scenario) for p in paths])
        min_n, max_n = _span([m["nodes_expanded"] for _p, m in runs])
        rows.append({
            "scenario_id": scenario.scenario_id, "algorithm": algorithm,
            "orders": len(variants), "found_count": len(paths),
            "distinct_paths": len({tuple(p) for p in paths}),
            "min_actions": min_l, "max_actions": max_l,
            "min_cost": min_c, "max_cost": max_c,
            "min_nodes": min_n, "max_nodes": max_n,
        })
    return rows


def write_sensitivity(rows, out_dir):
    """Write order_sensitivity.csv into `out_dir`."""
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "order_sensitivity.csv"), "w", newline="",
              encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=SENSITIVITY_FIELDS)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)
