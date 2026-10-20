"""Derived metrics for the research questions (plan §4.2, §12.4).

Takes the benchmark result rows and the |V|, |E| rows and adds, per
(scenario, algorithm), the comparisons each RQ needs:

- RQ1: cost gap vs the optimal cost C* (Dijkstra's total_cost).
- RQ2: length gap vs the minimum length L* (BFS's num_actions).
- RQ3: search effort relative to BFS, and coverage of the full state-space
  (nodes_expanded / |V|, edges_examined / |E|).
- RQ4: the outcome flags are carried through unchanged.

References follow plan §12.4: Dijkstra only for C, BFS only for L. Values
are None when they are undefined (no path, or a zero denominator).
"""

import csv
import os

ANALYSIS_FIELDS = (
    "scenario_id", "algorithm", "num_states", "num_edges",
    "path_found", "path_valid", "goal_reached",
    "total_cost", "optimal_cost", "cost_gap", "cost_ratio",
    "num_actions", "min_actions", "length_gap",
    "nodes_expanded", "edges_examined",
    "nodes_vs_bfs", "node_coverage", "edge_coverage",
)


def _ratio(a, b):
    if a is None or b is None or b == 0:
        return None
    return round(a / b, 4)


def _diff(a, b):
    if a is None or b is None:
        return None
    return a - b


def analyze(results, statespace):
    """Return one analysis row per result row (same order)."""
    sizes = {s["scenario_id"]: s for s in statespace}
    by_key = {(r["scenario_id"], r["algorithm"]): r for r in results}
    rows = []
    for r in results:
        sid = r["scenario_id"]
        size = sizes.get(sid, {})
        dij = by_key.get((sid, "dijkstra"), {})
        bfs = by_key.get((sid, "bfs"), {})
        c_opt = dij.get("total_cost")
        l_min = bfs.get("num_actions")
        rows.append({
            "scenario_id": sid, "algorithm": r["algorithm"],
            "num_states": size.get("num_states"),
            "num_edges": size.get("num_edges"),
            "path_found": r["path_found"], "path_valid": r["path_valid"],
            "goal_reached": r["goal_reached"],
            "total_cost": r["total_cost"], "optimal_cost": c_opt,
            "cost_gap": _diff(r["total_cost"], c_opt),
            "cost_ratio": _ratio(r["total_cost"], c_opt),
            "num_actions": r["num_actions"], "min_actions": l_min,
            "length_gap": _diff(r["num_actions"], l_min),
            "nodes_expanded": r["nodes_expanded"],
            "edges_examined": r["edges_examined"],
            "nodes_vs_bfs": _ratio(r["nodes_expanded"], bfs.get("nodes_expanded")),
            "node_coverage": _ratio(r["nodes_expanded"], size.get("num_states")),
            "edge_coverage": _ratio(r["edges_examined"], size.get("num_edges")),
        })
    return rows


def write_analysis(rows, out_dir):
    """Write analysis.csv into `out_dir`."""
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "analysis.csv"), "w", newline="",
              encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=ANALYSIS_FIELDS)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)
