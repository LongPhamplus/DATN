"""Tests for what-if patching, residual risk and the patch policies (week 3)."""

import json
import math
import os
import random

import pytest

from aapef import policies as P
from aapef.defense import (
    RiskOracle, curve_metrics, make_hmax, patch, patch_units, risk, risk_curve,
    risk_dijkstra, scenario_for_risk, sensitive_hosts,
)
from aapef.prob import ProbModel, cost_table
from aapef.scenario import build_scenario
from aapef.state import initial_state

SCEN_DIR = os.path.join(os.path.dirname(__file__), os.pardir, "scenarios")
K = 6


def _load(name):
    with open(os.path.join(SCEN_DIR, f"{name}.json"), encoding="utf-8") as fh:
        data = json.load(fh)
    return data, build_scenario(data)


@pytest.fixture(scope="module")
def small():
    data, sc = _load("small")
    costs = cost_table(data, ProbModel("cvss"))
    units = patch_units(data)
    return data, sc, costs, units, RiskOracle(sc, costs, units)


def test_units_of_converted_nasim_scenario(small):
    data, _, _, units, _ = small
    assert len(units) == 14 and set(units) == set(data["env_facts"])
    patched_actions = {a for acts in units.values() for a in acts}
    assert "capture_all" not in patched_actions
    assert not any(a.startswith("discover") for a in patched_actions)


def test_cve_units_are_cve_at_target_host():
    with open(os.path.join(SCEN_DIR, "lab-01.json"), encoding="utf-8") as fh:
        data = json.load(fh)   # CVE-source scenario: no integer costs
    sc = scenario_for_risk(data)
    assert len(sc.actions) == len(data["actions"])
    units = patch_units(data)
    cve_units = [u for u in units if u.startswith("CVE-")]
    assert cve_units and all("@" in u for u in cve_units)
    for u in cve_units:
        cve, host = u.split("@")
        for aid in units[u]:
            a = next(x for x in data["actions"] if x["id"] == aid)
            assert a["cve"] == cve
            assert any(e.get("host") == host for e in a["effects"] if e["type"] == "set_access")


def test_patch_returns_copy_without_unit_actions(small):
    _, sc, _, units, _ = small
    unit = "vuln_H1_0_e_http"
    patched = patch(sc, [unit], units)
    assert len(patched.actions) == len(sc.actions) - len(units[unit])
    assert not set(units[unit]) & {a.id for a in patched.actions}
    assert len(sc.actions) == 62   # original untouched
    with pytest.raises(KeyError):
        patch(sc, ["no_such_unit"], units)


@pytest.mark.parametrize("name", ["small", "small-linear"])
def test_astar_hmax_risk_equals_dijkstra(name):
    """The fast risk() must give the same P* as plain Dijkstra on many patch sets."""
    data, sc = _load(name)
    costs = cost_table(data, ProbModel("cvss"))
    units = patch_units(data)
    rng = random.Random(0)
    for _ in range(25):
        chosen = rng.sample(sorted(units), rng.randint(0, 4))
        s = patch(sc, chosen, units)
        assert risk(s, costs)[0] == pytest.approx(risk_dijkstra(s, costs)[0], abs=1e-15)


def test_hmax_is_zero_at_goal_and_inf_when_blocked(small):
    _, sc, costs, units, _ = small
    blocked = patch(sc, ["vuln_H1_0_e_http"], units)
    assert make_hmax(blocked, costs)(initial_state(blocked)) == math.inf
    h = make_hmax(sc, costs)
    p, path, _ = risk(sc, costs)
    assert 0 < h(initial_state(sc)) <= -math.log(p) + 1e-12   # admissible


def test_r0_and_curves_never_increase(small):
    data, sc, costs, units, oracle = small
    r0 = risk(sc, costs)[0]
    assert r0 == pytest.approx(math.exp(-sum(costs[a] for a in risk(sc, costs)[1])))
    orders = [P.random_order(units, s) for s in range(10)]
    orders += [P.by_probability(data, units, ProbModel("cvss")), P.context_greedy(oracle, K)]
    for order in orders:
        curve = risk_curve(oracle, order, K)
        assert curve[0] == pytest.approx(r0)
        assert all(b <= a for a, b in zip(curve, curve[1:]))


def test_greedy_and_optimal_on_small(small):
    """small has a single Internet-facing host; patching its http blocks every path."""
    data, _, _, units, oracle = small
    greedy = P.context_greedy(oracle, K)
    assert greedy == ["vuln_H1_0_e_http"]          # stops once P* = 0
    opt = P.optimal(oracle, K)
    assert [r for r, _ in opt][1:] == [0.0] * K
    for order in [greedy, P.random_order(units, 3)]:
        curve = risk_curve(oracle, order, K)
        assert all(o[0] <= c + 1e-15 for o, c in zip(opt, curve))


def test_policies_are_deterministic_and_complete(small):
    data, _, _, units, _ = small
    a = P.by_probability(data, units, ProbModel("cvss"))
    assert a == P.by_probability(data, units, ProbModel("cvss"))
    assert sorted(a) == sorted(units)
    assert P.random_order(units, 7) == P.random_order(units, 7)
    assert P.random_order(units, 7) != P.random_order(units, 8)


def test_sensitive_hosts_behind_virtual_goal():
    data, _ = _load("small")
    assert sensitive_hosts(data) == ["H2_0", "H4_0"]
    with open(os.path.join(SCEN_DIR, "lab-01.json"), encoding="utf-8") as fh:
        lab = json.load(fh)
    assert sensitive_hosts(lab) == [lab["goal"]["host"]]


def test_any_target_risk_is_max_over_targets():
    data, sc = _load("small-linear")
    costs = cost_table(data, ProbModel("cvss"))
    units = patch_units(data)
    targets = sensitive_hosts(data)
    anyo = RiskOracle(sc, costs, units, targets=targets)
    singles = [RiskOracle(sc, costs, units, targets=[t]) for t in targets]
    for chosen in ([], ["vuln_H1_0_e_http"], sorted(units)[:3]):
        assert anyo(chosen) == max(o(chosen) for o in singles)
    # any-target is harder to block than the AND goal of capture_all
    greedy = P.context_greedy(anyo, K)
    curve = risk_curve(anyo, greedy, K)
    assert curve_metrics(curve)["k_block"] == 2
    assert [r for r, _ in P.optimal(anyo, K)] == pytest.approx(curve)


def test_curve_metrics():
    assert curve_metrics([1.0, 0.5, 0.0]) == {"auc": 0.5, "k_block": 2}
    assert curve_metrics([1.0, 1.0, 1.0]) == {"auc": 1.0, "k_block": None}
    assert curve_metrics([0.0, 0.0]) == {"auc": 0.0, "k_block": 0}


def test_experiment_runner_writes_curves_and_summary(tmp_path):
    import csv
    from aapef.experiment import main
    main([os.path.join(SCEN_DIR, "small-linear.json"), "--models", "cvss", "--K", "3",
          "--seeds", "4", "--out", str(tmp_path)])
    with open(tmp_path / "summary.csv", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    policies = sorted({r["policy"] for r in rows})
    assert policies == ["by-probability", "context-greedy", "optimal", "random"]
    assert sum(r["policy"] == "random" for r in rows) == 4
    opt = next(r for r in rows if r["policy"] == "optimal")
    assert all(float(opt["auc"]) <= float(r["auc"]) + 1e-12 for r in rows)
    with open(tmp_path / "curves.csv", encoding="utf-8") as fh:
        assert sum(1 for _ in csv.DictReader(fh)) == len(rows) * 4   # k = 0..3
    assert json.loads((tmp_path / "meta.json").read_text())["K"] == 3
