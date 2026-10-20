"""Tests for the AAPEF MVP (plan §13).

Covers the shared transition rules, canonical state identity, the four search
algorithms, simulation/validation, state-space measurement, scenario
validation, and the edge cases (initial-goal, no-path). Deterministic metrics
(path, cost, nodes/edges) are asserted; runtime is not.
"""

import os

import pytest

from aapef.analyze import analyze
from aapef.benchmark import measure_state_space, run_benchmark, run_search
from aapef.scenario import ScenarioError, build_scenario, load_scenario
from aapef.search import bfs, dfs, dijkstra, greedy, make_heuristic
from aapef.simulate import path_cost, simulate_and_validate
from aapef.state import (
    State, apply, applicable, initial_state, is_goal, state_key, successors,
)

SCEN_DIR = os.path.join(os.path.dirname(__file__), os.pardir, "scenarios")


def scen(name):
    return load_scenario(os.path.join(SCEN_DIR, f"{name}.json"))


def _fns(scenario):
    return (lambda s: successors(s, scenario),
            lambda s: is_goal(s, scenario.goal),
            make_heuristic(scenario.goal))


# --- scenario loading & validation ------------------------------------------

def test_all_example_scenarios_load():
    for name in ("demo-small-01", "medium-01", "large-01",
                 "unreachable-01", "initial-goal-01"):
        scen(name)  # must not raise


def _minimal_data():
    return {
        "scenario_id": "t", "hosts": [{"id": "A"}, {"id": "B"}],
        "topology": [["A", "B"]], "env_facts": [],
        "initial_state": {"access": {"A": "user", "B": "none"}, "known": []},
        "actions": [{"id": "a1", "cost": 1,
                     "preconditions": [{"type": "access_at_least", "host": "A", "level": "user"}],
                     "effects": [{"type": "set_access", "host": "B", "level": "user"}]}],
        "goal": {"type": "access_at_least", "host": "B", "level": "user"},
    }


def test_validator_rejects_missing_host_in_access():
    data = _minimal_data()
    del data["initial_state"]["access"]["B"]  # missing host
    with pytest.raises(ScenarioError):
        build_scenario(data)


def test_validator_rejects_extra_host_in_access():
    data = _minimal_data()
    data["initial_state"]["access"]["Z"] = "none"  # unknown host
    with pytest.raises(ScenarioError):
        build_scenario(data)


def test_validator_rejects_invalid_level():
    data = _minimal_data()
    data["initial_state"]["access"]["A"] = "root"  # not in LEVELS
    with pytest.raises(ScenarioError):
        build_scenario(data)


def test_validator_rejects_negative_cost():
    data = _minimal_data()
    data["actions"][0]["cost"] = -1
    with pytest.raises(ScenarioError):
        build_scenario(data)


# --- transition semantics ----------------------------------------------------

def test_precondition_access_required():
    # discover_svcY_on_B needs access_at_least A user.
    s = scen("demo-small-01")
    discover = s.action_by_id("discover_svcY_on_B")
    assert applicable(initial_state(s), s, discover)  # A starts as user

    no_access = State({"A": "none", "B": "none", "C": "none"}, set())
    assert not applicable(no_access, s, discover)


def test_apply_is_pure_no_mutation():
    s = scen("demo-small-01")
    start = initial_state(s)
    before = state_key(start)
    discover = s.action_by_id("discover_svcY_on_B")
    _ = apply(start, discover)
    # successors must not mutate either
    _ = successors(start, s)
    assert state_key(start) == before
    assert start.known == set()


def test_set_access_never_downgrades():
    s = scen("demo-small-01")
    st = State({"A": "admin", "B": "none", "C": "none"}, set())
    # a hypothetical effect lowering A would be a no-op; use apply directly
    from aapef.scenario import Action
    down = Action("d", "down", [], 1, [{"type": "set_access", "host": "A", "level": "user"}], [])
    out = apply(st, down)
    assert out.access["A"] == "admin"  # unchanged


def test_canonical_identity_order_independent():
    a = State({"A": "user", "B": "none"}, {"f2", "f1"})
    b = State({"B": "none", "A": "user"}, {"f1", "f2"})
    assert state_key(a) == state_key(b)


def test_noop_excluded_from_successors():
    # Learning a fact already known yields a no-op -> not a successor.
    data = _minimal_data()
    data["actions"] = [{"id": "learn_again", "cost": 1,
                        "preconditions": [], "effects": [{"type": "learn", "fact": "f"}]}]
    data["initial_state"]["known"] = ["f"]  # already known
    s = build_scenario(data)
    assert successors(initial_state(s), s) == []


# --- algorithms: correctness -------------------------------------------------

def test_bfs_minimum_edges_on_medium():
    s = scen("medium-01")
    succ, goal, _ = _fns(s)
    path, m = bfs(initial_state(s), succ, goal)
    assert path == ["fast_pivot_C"]          # 1 edge (minimum length)
    assert len(path) == 1
    assert m["nodes_expanded"] >= 1


def test_dijkstra_minimum_cost_on_medium():
    s = scen("medium-01")
    succ, goal, _ = _fns(s)
    path, _ = dijkstra(initial_state(s), succ, goal)
    assert path_cost(path, s) == 6           # cheap route, cost 6
    assert path == ["discover_B", "gain_user_B", "gain_admin_C_via_B"]


def test_all_algorithms_find_a_valid_goal_path_on_small():
    s = scen("demo-small-01")
    succ, goal, heur = _fns(s)
    for algo in (bfs, dfs, dijkstra):
        path, _ = algo(initial_state(s), succ, goal)
        res = simulate_and_validate(path, s)
        assert res["valid"] and res["goal_reached"]
    gpath, _ = greedy(initial_state(s), succ, goal, heur)
    gres = simulate_and_validate(gpath, s)
    assert gres["valid"] and gres["goal_reached"]


def test_dijkstra_matches_bfs_cost_lower_bound_is_optimal():
    # Dijkstra cost must be <= any other algorithm's path cost on same scenario.
    s = scen("large-01")
    succ, goal, heur = _fns(s)
    dpath, _ = dijkstra(initial_state(s), succ, goal)
    dcost = path_cost(dpath, s)
    for algo in (bfs, dfs):
        p, _ = algo(initial_state(s), succ, goal)
        assert path_cost(p, s) >= dcost


# --- algorithms: no-path & initial-goal --------------------------------------

def test_no_path_returns_none_with_effort():
    s = scen("unreachable-01")
    succ, goal, heur = _fns(s)
    for algo_name, call in (("bfs", lambda: bfs(initial_state(s), succ, goal)),
                            ("dfs", lambda: dfs(initial_state(s), succ, goal)),
                            ("dijkstra", lambda: dijkstra(initial_state(s), succ, goal)),
                            ("greedy", lambda: greedy(initial_state(s), succ, goal, heur))):
        path, m = call()
        assert path is None, algo_name
        assert m["nodes_expanded"] >= 1       # effort was spent before concluding


def test_no_path_benchmark_row_schema():
    s = scen("unreachable-01")
    row = run_search(s, "bfs", runtime_repeats=1)
    assert row["path_found"] is False
    assert row["path_valid"] is None
    assert row["goal_reached"] is False
    assert row["num_actions"] is None
    assert row["total_cost"] is None
    assert row["nodes_expanded"] >= 1
    assert "runtime_ms" in row


def test_initial_state_already_at_goal():
    s = scen("initial-goal-01")
    succ, goal, heur = _fns(s)
    for path, m in (bfs(initial_state(s), succ, goal),
                    dfs(initial_state(s), succ, goal),
                    dijkstra(initial_state(s), succ, goal),
                    greedy(initial_state(s), succ, goal, heur)):
        assert path == []
        assert m["nodes_expanded"] == 0
        assert m["edges_examined"] == 0
    row = run_search(s, "bfs", runtime_repeats=1)
    assert row["path_found"] is True
    assert row["path_valid"] is True
    assert row["goal_reached"] is True
    assert row["num_actions"] == 0
    assert row["total_cost"] == 0


# --- simulation / validation -------------------------------------------------

def test_validation_rejects_noop_in_path():
    # Build a path whose second step repeats an effect already in effect.
    data = _minimal_data()
    data["actions"] = [
        {"id": "up_B", "cost": 1, "preconditions": [],
         "effects": [{"type": "set_access", "host": "B", "level": "user"}]},
        {"id": "up_B_again", "cost": 1, "preconditions": [],
         "effects": [{"type": "set_access", "host": "B", "level": "user"}]},
    ]
    s = build_scenario(data)
    res = simulate_and_validate(["up_B", "up_B_again"], s)
    assert res["valid"] is False
    assert "no-op" in res["reason"]


def test_validation_rejects_non_applicable_step():
    s = scen("demo-small-01")
    # pivot requires user on B, which we never gained -> not applicable first.
    res = simulate_and_validate(["pivot_and_admin_on_C"], s)
    assert res["valid"] is False


# --- state-space measurement (|V|, |E|) --------------------------------------

def test_statespace_diamond_counts_unique_states():
    # Two independent learnable facts -> states {}, {k1}, {k2}, {k1,k2}.
    data = _minimal_data()
    data["hosts"] = [{"id": "X"}]
    data["topology"] = []
    data["initial_state"] = {"access": {"X": "user"}, "known": []}
    data["actions"] = [
        {"id": "l1", "cost": 1, "preconditions": [], "effects": [{"type": "learn", "fact": "k1"}]},
        {"id": "l2", "cost": 1, "preconditions": [], "effects": [{"type": "learn", "fact": "k2"}]},
    ]
    data["goal"] = {"type": "access_at_least", "host": "X", "level": "admin"}
    s = build_scenario(data)
    info = measure_state_space(s)
    assert info["num_states"] == 4   # diamond merge counted once
    assert info["num_edges"] == 4    # {}->k1, {}->k2, k1->k1k2, k2->k1k2


def test_statespace_parallel_edges_counted_separately():
    # Two different actions both lead from {} to {k1}: two edges, two states.
    data = _minimal_data()
    data["hosts"] = [{"id": "X"}]
    data["topology"] = []
    data["initial_state"] = {"access": {"X": "user"}, "known": []}
    data["actions"] = [
        {"id": "a1", "cost": 1, "preconditions": [], "effects": [{"type": "learn", "fact": "k1"}]},
        {"id": "a2", "cost": 5, "preconditions": [], "effects": [{"type": "learn", "fact": "k1"}]},
    ]
    data["goal"] = {"type": "access_at_least", "host": "X", "level": "admin"}
    s = build_scenario(data)
    info = measure_state_space(s)
    assert info["num_states"] == 2
    assert info["num_edges"] == 2


def test_statespace_terminates_on_large():
    info = measure_state_space(scen("large-01"))
    assert info["num_states"] >= 1
    assert info["num_edges"] >= 1


# --- DFS traversal order -----------------------------------------------------

def test_dfs_follows_json_action_order():
    # Two one-step routes to goal; DFS must take the first action in JSON order.
    data = _minimal_data()
    data["hosts"] = [{"id": "A"}, {"id": "C"}]
    data["topology"] = [["A", "C"]]
    data["initial_state"] = {"access": {"A": "user", "C": "none"}, "known": []}
    data["actions"] = [
        {"id": "first_route", "cost": 1, "preconditions": [],
         "effects": [{"type": "set_access", "host": "C", "level": "admin"}]},
        {"id": "second_route", "cost": 1, "preconditions": [],
         "effects": [{"type": "set_access", "host": "C", "level": "admin"}]},
    ]
    data["goal"] = {"type": "access_at_least", "host": "C", "level": "admin"}
    s = build_scenario(data)
    succ, goal, _ = _fns(s)
    path, _ = dfs(initial_state(s), succ, goal)
    assert path == ["first_route"]


# --- determinism -------------------------------------------------------------

def test_benchmark_metrics_deterministic():
    s = scen("large-01")
    r1 = run_search(s, "dijkstra", runtime_repeats=1)
    r2 = run_search(s, "dijkstra", runtime_repeats=1)
    for field in ("path_found", "path_valid", "goal_reached", "num_actions",
                  "total_cost", "nodes_expanded", "edges_examined"):
        assert r1[field] == r2[field]


def test_runtime_reports_median_and_iqr():
    row = run_search(scen("demo-small-01"), "bfs", runtime_repeats=5)
    assert row["runtime_ms"] >= 0
    assert row["runtime_iqr_ms"] >= 0
    assert row["path"] == ["discover_svcY_on_B", "gain_user_on_B",
                           "pivot_and_admin_on_C"]


# --- analysis (RQ1-RQ4 derived metrics) --------------------------------------

def test_analysis_gaps_on_medium():
    results, statespace = run_benchmark([scen("medium-01")], runtime_repeats=1)
    rows = {r["algorithm"]: r for r in analyze(results, statespace)}
    # RQ1: Dijkstra is the cost reference; BFS's 1-step route costs 10 vs 6.
    assert rows["dijkstra"]["cost_gap"] == 0
    assert rows["bfs"]["cost_gap"] == 4
    # RQ2: BFS is the length reference; Dijkstra's cheap route is 2 steps longer.
    assert rows["bfs"]["length_gap"] == 0
    assert rows["dijkstra"]["length_gap"] == 2
    # RQ3: effort is relative to BFS and bounded by the full state-space.
    assert rows["bfs"]["nodes_vs_bfs"] == 1.0
    for r in rows.values():
        assert 0 <= r["node_coverage"] <= 1
        assert 0 <= r["edge_coverage"] <= 1


def test_analysis_no_path_gaps_are_none():
    results, statespace = run_benchmark([scen("unreachable-01")], runtime_repeats=1)
    for r in analyze(results, statespace):
        assert r["path_found"] is False
        assert r["cost_gap"] is None and r["length_gap"] is None
        assert r["nodes_expanded"] >= 1


def test_statespace_reports_measure_time():
    info = measure_state_space(scen("large-01"))
    assert info["measure_ms"] >= 0


def test_runtime_repeats_recorded():
    row = run_search(scen("demo-small-01"), "bfs", runtime_repeats=3)
    assert row["runtime_repeats"] == 3


# --- action-order sensitivity -------------------------------------------------

def test_permuted_orders_are_reproducible_and_keep_original_first():
    from aapef.sensitivity import permuted_orders
    s = scen("large-01")
    a = [[x.id for x in v.actions] for v in permuted_orders(s, 5, seed=7)]
    b = [[x.id for x in v.actions] for v in permuted_orders(s, 5, seed=7)]
    assert a == b
    assert a[0] == [x.id for x in s.actions]
    assert all(sorted(order) == sorted(a[0]) for order in a)


def test_order_sensitivity_optimal_values_are_order_invariant():
    from aapef.sensitivity import order_sensitivity
    for name in ("medium-01", "large-01"):
        rows = {r["algorithm"]: r
                for r in order_sensitivity(scen(name), ("bfs", "dijkstra"), 10, 42)}
        assert rows["bfs"]["min_actions"] == rows["bfs"]["max_actions"]
        assert rows["dijkstra"]["min_cost"] == rows["dijkstra"]["max_cost"]
        assert rows["bfs"]["found_count"] == rows["bfs"]["orders"] == 11


def test_order_sensitivity_no_path():
    from aapef.sensitivity import order_sensitivity
    for r in order_sensitivity(scen("unreachable-01"), ("bfs", "dfs"), 5, 42):
        assert r["found_count"] == 0
        assert r["min_actions"] is None and r["min_cost"] is None


# --- goal check ----------------------------------------------------------------

def test_goal_check_statuses():
    from aapef.benchmark import goal_check
    results, _ = run_benchmark([scen("medium-01"), scen("unreachable-01")],
                               runtime_repeats=1)
    rows = {r["scenario_id"]: r["status"] for r in goal_check(results)}
    assert rows == {"medium-01": "ok", "unreachable-01": "UNREACHABLE"}
    rows = {r["scenario_id"]: r["status"]
            for r in goal_check(results, ["unreachable-01", "medium-01"])}
    assert rows == {"medium-01": "UNEXPECTED-REACHABLE",
                    "unreachable-01": "expected-unreachable"}


def test_benchmark_strict_fails_on_unexpected_unreachable(tmp_path):
    from aapef.cli import main
    cfg = tmp_path / "cfg.json"
    cfg.write_text('{"scenarios": ["unreachable-01"], "runtime_repeats": 1}')
    with pytest.raises(SystemExit) as exc:
        main(["benchmark", "--config", str(cfg), "--scenarios-dir", SCEN_DIR,
              "--out", str(tmp_path / "out"), "--strict"])
    assert exc.value.code == 1


# --- A* (optional algorithm) ----------------------------------------------------

def test_astar_matches_dijkstra_cost_everywhere():
    from aapef.search import astar, make_admissible_heuristic
    from aapef.sensitivity import permuted_orders
    for name in ("demo-small-01", "medium-01", "large-01"):
        for variant in permuted_orders(scen(name), 10, seed=42):
            succ, goal, _ = _fns(variant)
            h = make_admissible_heuristic(variant)
            dpath, _ = dijkstra(initial_state(variant), succ, goal)
            apath, _ = astar(initial_state(variant), succ, goal, h)
            assert path_cost(apath, variant) == path_cost(dpath, variant)
            res = simulate_and_validate(apath, variant)
            assert res["valid"] and res["goal_reached"]


def test_admissible_heuristic_never_exceeds_true_remaining_cost():
    from aapef.search import make_admissible_heuristic
    s = scen("large-01")
    succ, goal, _ = _fns(s)
    h = make_admissible_heuristic(s)
    # true remaining cost from every reachable state via Dijkstra from there
    seen, stack = {}, [initial_state(s)]
    while stack:
        st = stack.pop()
        if state_key(st) in seen:
            continue
        seen[state_key(st)] = st
        stack.extend(n for _a, n, _c in succ(st))
    for st in seen.values():
        path, _ = dijkstra(st, succ, goal)
        true_cost = 0
        cur = st
        for aid in (path or []):
            a = s.action_by_id(aid)
            true_cost += a.cost
        if path is not None:
            assert h(st) <= true_cost
        # consistency: h(s) <= cost(s,s') + h(s')
        for _a, nxt, cost in succ(st):
            assert h(st) <= cost + h(nxt)


def test_astar_edge_cases():
    from aapef.search import astar, make_admissible_heuristic
    s = scen("initial-goal-01")
    succ, goal, _ = _fns(s)
    path, m = astar(initial_state(s), succ, goal, make_admissible_heuristic(s))
    assert path == [] and m["nodes_expanded"] == 0 and m["edges_examined"] == 0
    s = scen("unreachable-01")
    succ, goal, _ = _fns(s)
    path, m = astar(initial_state(s), succ, goal, make_admissible_heuristic(s))
    assert path is None and m["nodes_expanded"] >= 1


def test_benchmark_runs_astar_row():
    row = run_search(scen("medium-01"), "astar", runtime_repeats=1)
    assert row["path_found"] and row["path_valid"] and row["goal_reached"]
    assert row["total_cost"] == 6


# --- generated scenarios (scenarios/gen_rq3.sh) ---------------------------------

def _generated_ids():
    meta_dir = os.path.join(SCEN_DIR, "meta")
    return sorted(f[:-len(".meta.json")] for f in os.listdir(meta_dir)
                  if f.endswith(".meta.json"))


def test_generated_scenarios_load():
    ids = _generated_ids()
    assert len(ids) >= 10
    for sid in ids:
        assert scen(sid).scenario_id == sid


def test_generated_state_space_matches_generator_meta():
    import json
    # Small/medium ones only, to keep the suite fast.
    for sid in ("size-v132", "size-v352", "trap-01", "cycles-01",
                "unreachable-02", "initial-goal-02"):
        with open(os.path.join(SCEN_DIR, "meta", f"{sid}.meta.json"),
                  encoding="utf-8") as fh:
            meta = json.load(fh)["state_space"]
        info = measure_state_space(scen(sid))
        assert (info["num_states"], info["num_edges"]) == (meta["V"], meta["E"])


# --- demo command ---------------------------------------------------------------

def test_demo_prints_tradeoff_on_medium(capsys):
    from aapef.cli import main
    main(["demo", "--scenario", os.path.join(SCEN_DIR, "medium-01.json"),
          "--repeats", "1"])
    out = capsys.readouterr().out
    assert "medium-01" in out and "|V|=6" in out
    assert "fewest actions (L=1): bfs, greedy" in out
    assert "lowest cost    (C=6)" in out and "dijkstra" in out
    assert "L != C" in out


def test_demo_no_path_message(capsys):
    from aapef.cli import main
    main(["demo", "--scenario", os.path.join(SCEN_DIR, "unreachable-01.json"),
          "--repeats", "1"])
    assert "no algorithm found a valid path" in capsys.readouterr().out
