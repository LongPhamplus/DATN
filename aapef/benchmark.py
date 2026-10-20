"""Benchmark runner and result export (plan §12).

Runs every algorithm on every scenario under identical conditions, records the
metrics, and exports them as CSV and JSON. Also measures the full reachable
state-space size |V|, |E| per scenario as a separate reference step (plan §12.5)
that is kept out of each algorithm's runtime.
"""

import csv
import json
import os
import statistics
from time import perf_counter

from .search import (
    ALGORITHMS, make_admissible_heuristic, make_heuristic, run_algorithm,
)
from .simulate import path_cost, simulate_and_validate
from .state import initial_state, is_goal, state_key, successors

# Columns of a benchmark result row (plan §12.3).
RESULT_FIELDS = (
    "scenario_id", "algorithm",
    "path_found", "path_valid", "goal_reached",
    "num_actions", "total_cost",
    "nodes_expanded", "edges_examined", "runtime_ms", "runtime_iqr_ms",
    "runtime_repeats",
)

STATESPACE_FIELDS = ("scenario_id", "num_states", "num_edges", "measure_ms")

# Untimed runs before measuring, to warm caches/allocator (plan §12.3).
WARMUP_RUNS = 2


def _iqr(samples):
    """Interquartile range (Q3 - Q1); 0 when there are too few samples."""
    if len(samples) < 2:
        return 0.0
    q1, _q2, q3 = statistics.quantiles(samples, n=4, method="inclusive")
    return q3 - q1


def measure_state_space(scenario):
    """Measure |V| and |E| of the full reachable state-space (plan §12.5).

    Traverses every state reachable from the initial state using the same
    `successors` function the algorithms use. `|V|` is the number of distinct
    states (by `state_key`); `|E|` is the number of directed edges generated
    (parallel edges from different actions to the same state are counted
    separately). No-ops are not edges (already excluded by `successors`). The
    visited set guarantees termination on duplicate states (and the monotonic
    effect model means true cycles cannot occur in the first place).
    `measure_ms` is the wall time of this traversal, recorded so the practical
    size limit of a scenario is visible; it is unrelated to `runtime_ms`.
    """
    t0 = perf_counter()
    start = initial_state(scenario)
    visited = {state_key(start)}
    edges = 0
    stack = [start]
    while stack:
        state = stack.pop()
        for _action, nxt, _cost in successors(state, scenario):
            edges += 1
            k = state_key(nxt)
            if k not in visited:
                visited.add(k)
                stack.append(nxt)
    return {"scenario_id": scenario.scenario_id, "num_states": len(visited),
            "num_edges": edges,
            "measure_ms": round((perf_counter() - t0) * 1000.0, 3)}


def _search_inputs(scenario):
    """The inputs every algorithm runs on, in `run_algorithm` argument order."""
    goal = scenario.goal
    return (initial_state(scenario),
            lambda state: successors(state, scenario),
            lambda state: is_goal(state, goal),
            make_heuristic(goal),
            make_admissible_heuristic(scenario))


def search_once(scenario, algorithm):
    """One untimed search run. Returns (path, metrics)."""
    return run_algorithm(algorithm, *_search_inputs(scenario))


def run_search(scenario, algorithm, runtime_repeats=30):
    """Run one algorithm on one scenario; return a result row (plan §12.3).

    Search metrics (nodes/edges) are deterministic, so they come from a single
    run. Runtime is measured over `runtime_repeats` runs after `WARMUP_RUNS`
    untimed runs, and reported as median + IQR in milliseconds (plan §12.3).
    The row also carries `path` (list of action ids, or None); it is written
    to the JSON export but not to the CSV.
    """
    inputs = _search_inputs(scenario)

    # One deterministic run for path + search-effort metrics.
    path, metrics = run_algorithm(algorithm, *inputs)

    # Timed runs (search loop only; excludes load/simulation/validation/export).
    for _ in range(WARMUP_RUNS):
        run_algorithm(algorithm, *inputs)
    samples = []
    for _ in range(max(1, runtime_repeats)):
        t0 = perf_counter()
        run_algorithm(algorithm, *inputs)
        samples.append((perf_counter() - t0) * 1000.0)
    runtime_ms = statistics.median(samples)
    runtime_iqr_ms = _iqr(samples)
    repeats = len(samples)

    if path is None:
        # No-path schema (plan §12.3 / §4.2).
        return {
            "scenario_id": scenario.scenario_id, "algorithm": algorithm,
            "path_found": False, "path_valid": None, "goal_reached": False,
            "num_actions": None, "total_cost": None,
            "nodes_expanded": metrics["nodes_expanded"],
            "edges_examined": metrics["edges_examined"],
            "runtime_ms": round(runtime_ms, 6),
            "runtime_iqr_ms": round(runtime_iqr_ms, 6),
            "runtime_repeats": repeats,
            "path": None,
        }

    result = simulate_and_validate(path, scenario)
    return {
        "scenario_id": scenario.scenario_id, "algorithm": algorithm,
        "path_found": True,
        "path_valid": result["valid"],
        "goal_reached": result["goal_reached"],
        "num_actions": len(path),
        "total_cost": path_cost(path, scenario),
        "nodes_expanded": metrics["nodes_expanded"],
        "edges_examined": metrics["edges_examined"],
        "runtime_ms": round(runtime_ms, 6),
        "runtime_iqr_ms": round(runtime_iqr_ms, 6),
        "runtime_repeats": repeats,
        "path": path,
    }


def goal_check(results, expect_unreachable=()):
    """Per-scenario check that the goal was reached as expected.

    A scenario is `ok` when at least one algorithm produced a valid path that
    reaches the goal, `expected-unreachable` when no algorithm did and the
    scenario is listed in `expect_unreachable`. Anything else is a problem:
    `UNREACHABLE` (goal never reached, not expected) or `UNEXPECTED-REACHABLE`
    (listed as unreachable but some algorithm reached it). Returns rows in
    first-seen scenario order.
    """
    reached = {}
    for r in results:
        hit = bool(r["goal_reached"]) and r["path_valid"] is True
        reached.setdefault(r["scenario_id"], [])
        if hit:
            reached[r["scenario_id"]].append(r["algorithm"])
    expected = set(expect_unreachable)
    rows = []
    for sid, algos in reached.items():
        if sid in expected:
            status = "UNEXPECTED-REACHABLE" if algos else "expected-unreachable"
        else:
            status = "ok" if algos else "UNREACHABLE"
        rows.append({"scenario_id": sid, "status": status,
                     "reached_by": " ".join(algos)})
    return rows


def run_benchmark(scenarios, algorithms=ALGORITHMS, runtime_repeats=30):
    """Run every algorithm on every scenario. Returns (results, statespace)."""
    results = []
    statespace = []
    for scenario in scenarios:
        statespace.append(measure_state_space(scenario))
        for algorithm in algorithms:
            results.append(run_search(scenario, algorithm, runtime_repeats))
    return results, statespace


def write_results(results, statespace, out_dir):
    """Write results.csv, statespace.csv and benchmark.json into `out_dir`."""
    os.makedirs(out_dir, exist_ok=True)

    with open(os.path.join(out_dir, "results.csv"), "w", newline="",
              encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=RESULT_FIELDS,
                                extrasaction="ignore")  # path -> JSON only
        writer.writeheader()
        for row in results:
            writer.writerow(row)

    with open(os.path.join(out_dir, "statespace.csv"), "w", newline="",
              encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=STATESPACE_FIELDS)
        writer.writeheader()
        for row in statespace:
            writer.writerow(row)

    with open(os.path.join(out_dir, "benchmark.json"), "w",
              encoding="utf-8") as fh:
        json.dump({"results": results, "statespace": statespace}, fh, indent=2)
