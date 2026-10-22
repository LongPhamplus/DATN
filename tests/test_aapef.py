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


def _generated(sid):
    """Load a generated scenario. CVE-source ones (`cve-*`) have no cost fields,
    so their recosted copy in scenarios/cvss/ is loaded instead."""
    if sid.startswith("cve-"):
        return load_scenario(os.path.join(SCEN_DIR, "cvss", f"{sid}.json"))
    return scen(sid)


def test_generated_scenarios_load():
    ids = _generated_ids()
    assert len(ids) >= 21
    for sid in ids:
        assert _generated(sid).scenario_id == sid


def test_generated_state_space_matches_generator_meta():
    import json
    # Small/medium ones only, to keep the suite fast.
    for sid in ("size-v132", "size-v352", "trap-01", "cycles-01",
                "unreachable-02", "initial-goal-02",
                "cve-h5-v24", "cve-size-v112", "cve-cycles-v72",
                "cve-unreachable-v21", "cve-initial-goal-v10"):
        with open(os.path.join(SCEN_DIR, "meta", f"{sid}.meta.json"),
                  encoding="utf-8") as fh:
            meta = json.load(fh)["state_space"]
        info = measure_state_space(_generated(sid))
        assert (info["num_states"], info["num_edges"]) == (meta["V"], meta["E"])


def test_cve_source_scenarios_have_no_cost_and_valid_cves():
    import json
    catalog = _catalog()
    for sid in _generated_ids():
        if not sid.startswith("cve-"):
            continue
        with open(os.path.join(SCEN_DIR, f"{sid}.json"), encoding="utf-8") as fh:
            data = json.load(fh)
        for action in data["actions"]:
            assert "cost" not in action, (sid, action["id"])
            if "cve" in action:
                assert action["cve"] in catalog, (sid, action["cve"])


def test_return_actions_never_create_edges():
    # Regression: an older generator let return_* raise access when a shortcut
    # bypassed a host, so cycles-01 had 240 non-no-op edges from them.
    from aapef.state import initial_state, state_key, successors
    for sid in ("cycles-01", "cve-cycles-v72"):
        s = _generated(sid)
        assert any(a.id.startswith("return_") for a in s.actions)
        seen, stack = set(), [initial_state(s)]
        while stack:
            st = stack.pop()
            if state_key(st) in seen:
                continue
            seen.add(state_key(st))
            for action, nxt, _cost in successors(st, s):
                assert not action.id.startswith("return_"), (sid, action.id)
                stack.append(nxt)


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


# --- CVSS-derived costs (plan §9.3) ---------------------------------------------

def _raw(name):
    import json
    with open(os.path.join(SCEN_DIR, f"{name}.json"), encoding="utf-8") as fh:
        return json.load(fh)


def test_cvss_exploitability_matches_spec():
    from aapef.cvss import MAX_EXPLOITABILITY, exploitability
    assert abs(MAX_EXPLOITABILITY - 3.887) < 0.001
    assert abs(exploitability({"AV": "N", "AC": "L", "PR": "L", "UI": "N"}) - 2.835) < 0.001
    assert abs(exploitability({"AV": "N", "AC": "L", "PR": "H", "UI": "N"}) - 1.235) < 0.001


def test_cvss_vector_costs():
    from aapef.cvss import CostModel, vector_cost
    m = CostModel()

    def cost(av, ac, pr, ui):
        return vector_cost({"AV": av, "AC": ac, "PR": pr, "UI": ui}, m)

    assert cost("N", "L", "N", "N") == 9
    assert cost("N", "L", "L", "N") == 13
    assert cost("N", "L", "H", "N") == 21
    assert cost("L", "L", "N", "N") == 14
    assert cost("N", "H", "L", "N") == 18


def test_cvss_cost_never_decreases_with_difficulty():
    from aapef.cvss import CostModel, vector_cost
    easiest_to_hardest = {"AV": "NALP", "AC": "LH", "PR": "NLH", "UI": "NR"}
    best = {"AV": "N", "AC": "L", "PR": "N", "UI": "N"}
    m = CostModel()
    for metric, order in easiest_to_hardest.items():
        costs = [vector_cost({**best, metric: v}, m) for v in order]
        assert costs == sorted(costs), metric


def test_cvss_derives_vector_from_structure():
    from aapef.cvss import CostModel, recost_scenario
    out = recost_scenario(_raw("medium-01"), CostModel())
    by_id = {a["id"]: a for a in out["actions"]}
    assert by_id["discover_B"]["cost_basis"] == "discovery"
    assert by_id["discover_B"]["cost"] == 1 and "cvss" not in by_id["discover_B"]
    # no reachable precondition -> AV:L; no access requirement -> PR:N
    assert by_id["gain_user_B"]["cvss"] == {"AV": "L", "AC": "L", "PR": "N", "UI": "N"}
    assert by_id["gain_user_B"]["cost"] == 14
    # reachable + access_at_least user -> AV:N, PR:L
    assert by_id["gain_admin_C_via_B"]["cvss"] == {"AV": "N", "AC": "L", "PR": "L", "UI": "N"}
    assert by_id["gain_admin_C_via_B"]["cost"] == 13
    assert out["cost_model"]["name"] == "cvss-3.1-exploitability-neglog"


def test_cvss_override_applies():
    from aapef.cvss import CostModel, recost_scenario
    data = _raw("medium-01")
    for a in data["actions"]:
        if a["id"] == "fast_pivot_C":
            a["cvss_override"] = {"AC": "H"}
    out = recost_scenario(data, CostModel())
    pivot = next(a for a in out["actions"] if a["id"] == "fast_pivot_C")
    assert pivot["cvss"]["AC"] == "H" and pivot["cost"] == 18


def test_cvss_override_rejected_when_invalid():
    from aapef.cvss import CostModel, recost_scenario
    for bad in ({"AV": "X"}, {"ZZ": "N"}, "N"):
        data = _raw("medium-01")
        data["actions"][2]["cvss_override"] = bad
        with pytest.raises(ValueError):
            recost_scenario(data, CostModel())
    data = _raw("medium-01")
    data["actions"][0]["cvss_override"] = {"AC": "H"}  # discovery action
    with pytest.raises(ValueError):
        recost_scenario(data, CostModel())


def test_cvss_model_parameters_validated():
    from aapef.cvss import CostModel
    for bad in (CostModel(p_norm=1.0), CostModel(discovery_p=0),
                CostModel(scale=0), CostModel(default_ac="X")):
        with pytest.raises(ValueError):
            bad.validate()


def test_recost_is_idempotent_and_result_loads():
    from aapef.cvss import CostModel, recost_scenario
    m = CostModel()
    once = recost_scenario(_raw("large-01"), m)
    assert recost_scenario(once, m) == once
    s = build_scenario(once)
    assert all(isinstance(a.cost, int) and a.cost >= 0 for a in s.actions)


def test_validator_rejects_bad_cvss_fields():
    data = _minimal_data()
    data["actions"][0]["cvss_override"] = {"AV": "Q"}
    with pytest.raises(ScenarioError):
        build_scenario(data)
    data = _minimal_data()
    data["actions"][0]["cvss"] = {"AV": "N"}  # a full vector is required here
    with pytest.raises(ScenarioError):
        build_scenario(data)


def test_recost_cli_writes_scenarios_and_skips_configs(tmp_path, capsys):
    from aapef.cli import main
    out_dir = tmp_path / "cvss"
    main(["recost", "--out-dir", str(out_dir),
          os.path.join(SCEN_DIR, "medium-01.json"),
          os.path.join(SCEN_DIR, "benchmark_config.json")])
    assert "skip" in capsys.readouterr().out
    assert (out_dir / "medium-01.json").exists()
    assert not (out_dir / "benchmark_config.json").exists()
    s = load_scenario(str(out_dir / "medium-01.json"))
    assert {a.id: a.cost for a in s.actions}["fast_pivot_C"] == 13


def test_cvss_costs_remove_built_in_tradeoff_on_medium():
    # Finding, not a requirement: with vectors derived from structure alone the
    # one-step route is also the cheapest, so BFS and Dijkstra agree (L == C).
    from aapef.cvss import CostModel, recost_scenario
    s = build_scenario(recost_scenario(_raw("medium-01"), CostModel()))
    succ, goal, _ = _fns(s)
    bpath, _ = bfs(initial_state(s), succ, goal)
    dpath, _ = dijkstra(initial_state(s), succ, goal)
    assert bpath == dpath == ["fast_pivot_C"]
    assert path_cost(dpath, s) == 13


def test_cvss_single_step_cost_bounds():
    # The whole CVSS range maps to costs 9..44 (scale 10, p = E/10): this bounds
    # how expensive one step can be relative to a chain of ordinary steps.
    from aapef.cvss import CostModel, vector_cost
    m = CostModel()
    assert vector_cost({"AV": "N", "AC": "L", "PR": "N", "UI": "N"}, m) == 9
    assert vector_cost({"AV": "P", "AC": "H", "PR": "H", "UI": "R"}, m) == 44


# --- CVE-based vectors from NVD records (plan §9.3) -----------------------------

def _catalog():
    from aapef.cvss import load_catalog
    return load_catalog(os.path.join(SCEN_DIR, "cve_catalog.json"))


def test_scope_changed_changes_pr_weight_only():
    from aapef.cvss import exploitability
    low = {"AV": "N", "AC": "L", "PR": "L", "UI": "N"}
    assert abs(exploitability(low) - 2.835) < 0.001
    assert abs(exploitability({**low, "S": "C"}) - 3.110) < 0.001
    none = {"AV": "N", "AC": "L", "PR": "N", "UI": "N"}
    assert exploitability({**none, "S": "C"}) == exploitability(none)


def test_parse_vector_string():
    from aapef.cvss import parse_vector_string
    got = parse_vector_string("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H")
    assert got == {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "C"}
    for bad in ("AV:N/AC:L", "CVSS:2.0/AV:N/AC:L/PR:N/UI:N",
                "CVSS:3.1/AV:X/AC:L/PR:N/UI:N", "CVSS:3.1/AV:N/AC:L", None):
        with pytest.raises(ValueError):
            parse_vector_string(bad)


def test_catalog_vectors_reproduce_nvd_exploitability_scores():
    # Independent check against the Exploitability score NVD published for each
    # record: catches a mistyped vector or a wrong weight.
    from aapef.cvss import exploitability
    catalog = _catalog()
    assert len(catalog) >= 9
    for cve, entry in catalog.items():
        assert round(exploitability(entry["parsed"]), 1) == entry["nvd_exploitability"], cve
        assert entry["kev_added"], cve


def test_cve_action_uses_catalog_vector():
    from aapef.cvss import CostModel, recost_scenario
    data = _raw("medium-01")
    data["actions"][3]["cve"] = "CVE-2016-5195"      # fast_pivot_C: AV:L/AC:H/PR:L
    out = recost_scenario(data, CostModel(), _catalog())
    action = out["actions"][3]
    assert action["cost_basis"] == "cve" and action["cvss"]["AC"] == "H"
    assert action["cost"] == 23
    assert out["cost_model"]["cves"] == ["CVE-2016-5195"]
    assert recost_scenario(out, CostModel(), _catalog()) == out  # idempotent


def test_cve_misuse_is_rejected():
    from aapef.cvss import CostModel, recost_scenario
    cat = _catalog()

    def attempt(index, **fields):
        data = _raw("medium-01")
        data["actions"][index].update(fields)
        return lambda c=cat: recost_scenario(data, CostModel(), c)

    for call in (attempt(3, cve="CVE-2016-5195", cvss_override={"AC": "L"}),  # both
                 attempt(0, cve="CVE-2016-5195"),     # information-gathering action
                 attempt(3, cve="CVE-1999-0001")):    # not in the catalog
        with pytest.raises(ValueError):
            call()
    data = _raw("medium-01")
    data["actions"][3]["cve"] = "CVE-2016-5195"
    with pytest.raises(ValueError):                   # no catalog supplied
        recost_scenario(data, CostModel(), None)


def test_validator_rejects_malformed_cve_id():
    data = _minimal_data()
    data["actions"][0]["cve"] = "log4shell"
    with pytest.raises(ScenarioError):
        build_scenario(data)


# --- lab-01: a scenario costed from real CVEs ----------------------------------

def test_lab01_costs_come_from_the_catalog_and_match_committed_output():
    import json
    from aapef.cvss import CostModel, recost_scenario
    out = recost_scenario(_raw("lab-01"), CostModel(), _catalog())
    with open(os.path.join(SCEN_DIR, "cvss", "lab-01.json"), encoding="utf-8") as fh:
        assert json.load(fh) == out
    costs = {a["id"]: a["cost"] for a in out["actions"]}
    assert costs["exploit_web_struts"] == costs["exploit_web_log4shell"] == 9
    assert costs["exploit_app_bluekeep"] == 9 and costs["exploit_app_eternalblue"] == 13
    assert costs["privesc_web_dirtycow"] == 23
    assert costs["privesc_web_sudo"] == costs["privesc_web_pwnkit"] == 17
    assert costs["discover_web"] == 1


def test_lab01_has_a_data_derived_length_cost_tradeoff():
    # Finding for this designed scenario (not a claim about networks in general).
    s = load_scenario(os.path.join(SCEN_DIR, "cvss", "lab-01.json"))
    succ, goal, heur = _fns(s)
    bpath, _ = bfs(initial_state(s), succ, goal)
    dpath, _ = dijkstra(initial_state(s), succ, goal)
    assert len(bpath) == 5 and len(dpath) == 6          # L* = 5, route of C* has 6
    assert path_cost(dpath, s) == 30 and path_cost(bpath, s) > 30
    from aapef.search import astar, make_admissible_heuristic
    apath, _ = astar(initial_state(s), succ, goal, make_admissible_heuristic(s))
    assert path_cost(apath, s) == 30


# --- CVE catalog shape shared with scen_gen.py ----------------------------------

def test_catalog_accepts_cves_list_and_entries_map(tmp_path):
    import json
    from aapef.cvss import load_catalog
    rec = {"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}
    as_list = tmp_path / "list.json"
    as_list.write_text(json.dumps({"cves": [{"id": "CVE-2020-0001", **rec}]}))
    as_map = tmp_path / "map.json"
    as_map.write_text(json.dumps({"entries": {"CVE-2020-0001": rec}}))
    assert load_catalog(str(as_list)).keys() == load_catalog(str(as_map)).keys()
    dup = tmp_path / "dup.json"
    dup.write_text(json.dumps({"cves": [{"id": "CVE-2020-0001", **rec},
                                        {"id": "CVE-2020-0001", **rec}]}))
    with pytest.raises(ValueError):
        load_catalog(str(dup))


def test_catalog_records_have_a_canonical_attack_role():
    # scen_gen.py groups CVEs by this field; every role it needs must be present.
    canonical = {"initial-access", "lateral", "privesc", "domain-takeover", "client-side"}
    roles = {e["attack_role"] for e in _catalog().values()}
    assert roles == canonical


# --- error messages for CVE-source scenarios -------------------------------------

def test_loading_a_cve_source_file_explains_how_to_recost():
    with pytest.raises(ScenarioError) as exc:
        load_scenario(os.path.join(SCEN_DIR, "cve-h5-v24.json"))
    msg = str(exc.value)
    assert "no 'cost' field" in msg and "recost" in msg and "scenarios/cvss" in msg


def test_missing_cost_without_cve_gets_no_recost_hint():
    data = _minimal_data()
    del data["actions"][0]["cost"]
    with pytest.raises(ScenarioError) as exc:
        build_scenario(data)
    assert "no 'cost' field" in str(exc.value) and "recost" not in str(exc.value)


def test_recost_without_catalog_mentions_the_catalog_option():
    from aapef.cvss import CostModel, recost_scenario
    data = _raw("medium-01")
    data["actions"][3]["cve"] = "CVE-2016-5195"
    with pytest.raises(ValueError) as exc:
        recost_scenario(data, CostModel(), None)
    assert "--catalog" in str(exc.value)
