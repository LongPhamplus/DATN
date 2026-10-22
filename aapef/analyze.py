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


# --- printed summary (benchmark --summary) -----------------------------------

def _per_scenario(results):
    by = {}
    for r in results:
        by.setdefault(r["scenario_id"], {})[r["algorithm"]] = r
    return by


def summarize(results):
    """Aggregate per algorithm over the scenarios that have a non-empty path.

    C* is Dijkstra's cost and L* is BFS's length (plan §12.4), so scenarios are
    kept only when both algorithms ran and found a path. Returns
    (rows, scenario_ids): one dict per algorithm, plus the ids that were used.
    """
    by = _per_scenario(results)
    ids = [s for s, rows in by.items()
           if "dijkstra" in rows and "bfs" in rows
           and rows["dijkstra"]["path_found"] and rows["dijkstra"]["num_actions"]]
    cstar = {s: by[s]["dijkstra"]["total_cost"] for s in ids}
    lstar = {s: by[s]["bfs"]["num_actions"] for s in ids}
    algos = []
    for r in results:
        if r["algorithm"] not in algos:
            algos.append(r["algorithm"])
    rows = []
    for a in algos:
        sel = [(s, by[s][a]) for s in ids if a in by[s] and by[s][a]["path_found"]]
        if not sel:
            continue
        ratios = [r["total_cost"] / cstar[s] for s, r in sel]
        gaps = [r["num_actions"] - lstar[s] for s, r in sel]
        effort = [r["nodes_expanded"] for _s, r in sel]
        rows.append({
            "algorithm": a, "scenarios": len(sel),
            "valid": sum(r["path_valid"] is True for _s, r in sel),
            "cost_optimal": sum(r["total_cost"] == cstar[s] for s, r in sel),
            "length_optimal": sum(r["num_actions"] == lstar[s] for s, r in sel),
            "cost_ratio_mean": sum(ratios) / len(ratios),
            "cost_ratio_max": max(ratios),
            "length_gap_mean": sum(gaps) / len(gaps),
            "length_gap_max": max(gaps),
            "nodes_median": sorted(effort)[len(effort) // 2],
            "nodes_total": sum(effort),
        })
    return rows, ids


def format_summary(results, statespace):
    """Plain-text tables: aggregate per algorithm, then one row per scenario."""
    rows, ids = summarize(results)
    if not rows:
        return ("summary: needs 'bfs' and 'dijkstra' in the config and at least "
                "one scenario with a path")
    by = _per_scenario(results)
    size = {s["scenario_id"]: s["num_states"] for s in statespace}
    skipped = [s for s in by if s not in ids]
    lines = [f"summary over {len(ids)} scenario(s) with a path"
             + (f" (skipped, no path or empty path: {', '.join(skipped)})" if skipped else ""),
             "", "per algorithm:"]
    head = (f"  {'algorithm':<10}{'valid':>7}{'C opt':>7}{'L min':>7}"
            f"{'C/C* avg':>10}{'C/C* max':>10}{'L-L* avg':>10}{'L-L* max':>10}"
            f"{'E_n med':>9}{'E_n sum':>9}")
    lines.append(head)
    for r in rows:
        n = r["scenarios"]
        lines.append(
            f"  {r['algorithm']:<10}{str(r['valid']) + '/' + str(n):>7}"
            f"{str(r['cost_optimal']) + '/' + str(n):>7}"
            f"{str(r['length_optimal']) + '/' + str(n):>7}"
            f"{r['cost_ratio_mean']:>10.2f}{r['cost_ratio_max']:>10.2f}"
            f"{r['length_gap_mean']:>10.1f}{r['length_gap_max']:>10}"
            f"{r['nodes_median']:>9}{r['nodes_total']:>9}")
    algos = [r["algorithm"] for r in rows]
    lines += ["", "per scenario (cell = C/E_n):",
              f"  {'scenario':<22}{'|V|':>7}{'C*':>5}{'L*':>4}"
              + "".join(f"{a:>10}" for a in algos)]
    for s in ids:
        cells = "".join(
            f"{str(by[s][a]['total_cost']) + '/' + str(by[s][a]['nodes_expanded']):>10}"
            if a in by[s] else f"{'-':>10}" for a in algos)
        lines.append(f"  {s:<22}{size.get(s, '-'):>7}"
                     f"{by[s]['dijkstra']['total_cost']:>5}{by[s]['bfs']['num_actions']:>4}"
                     + cells)
    return "\n".join(lines)
