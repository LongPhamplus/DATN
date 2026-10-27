"""What-if patching and residual risk (MasterPlan §6.2, §7.1-7.2).

Patch unit = one vulnerability instance on one host (ThietKe_ThiNghiem §10):
  - an action with a `cve` belongs to unit "<CVE>@<host>", host = the host its
    `set_access` effect targets;
  - otherwise each `env_fact` precondition of the action is a unit (converted
    NASim scenarios: "vuln_<host>_<exploit>").
Actions with neither (scans, the virtual `capture_all`, credential reuse) are
in no unit and cannot be patched.

Patching a set of units returns a copy of the scenario without the actions of
those units; the original is never changed and the transition rules are the
ones of `state.py`.

Risk P* = exp(-C*), C* = cheapest total of the real-valued costs (-ln p, see
`prob.py`) found by Dijkstra; P* = 0 when the goal cannot be reached.
"""

import dataclasses
import math

from .prob import weighted_successors
from .scenario import build_scenario
from .search import astar, dijkstra
from .state import LEVELS, initial_state, is_goal, state_key


def _target(action):
    hosts = {e["host"] for e in action["effects"] if e["type"] == "set_access"}
    if len(hosts) != 1:
        raise ValueError(f"action {action['id']!r}: a cve action needs exactly one "
                         f"set_access target, got {sorted(hosts)}")
    return hosts.pop()


def patch_units(data):
    """{unit id: [action ids]} for raw scenario dict `data`, units sorted by id."""
    units = {}
    for a in data["actions"]:
        if a.get("cve"):
            keys = [f"{a['cve']}@{_target(a)}"]
        else:
            keys = [p["fact"] for p in a.get("preconditions", []) if p["type"] == "env_fact"]
        for k in keys:
            units.setdefault(k, []).append(a["id"])
    return {k: units[k] for k in sorted(units)}


def scenario_for_risk(data):
    """Validated Scenario of raw dict `data` for risk computation.

    `risk` uses the real-valued costs of `prob.cost_table`, never the integer
    `cost` field, so CVE-source scenarios (which have no `cost` until
    `aapef recost`) are accepted: a missing cost is set to 0 in a copy.
    """
    copy = dict(data, actions=[a if "cost" in a else {**a, "cost": 0}
                               for a in data["actions"]])
    return build_scenario(copy)


def patch(scenario, units, unit_actions):
    """Copy of `scenario` without the actions of `units` (ids of `unit_actions`)."""
    removed = set()
    for u in units:
        if u not in unit_actions:
            raise KeyError(f"unknown patch unit {u!r}")
        removed.update(unit_actions[u])
    return dataclasses.replace(
        scenario, actions=[a for a in scenario.actions if a.id not in removed])


def _relaxed_actions(scenario, costs):
    """Actions as (precondition facts, effect facts, cost) for `h_max`.

    Static preconditions (env_fact, reachable) are checked once here. Access
    facts are (host, rank); gaining admin also gives user.
    """
    out = []
    for a in scenario.actions:
        c = costs[a.id]
        if c == math.inf:
            continue
        pres, ok = [], True
        for p in a.preconditions:
            t = p["type"]
            if t == "env_fact":
                ok = ok and p["fact"] in scenario.env_facts
            elif t == "reachable":
                ok = ok and (p["from"], p["to"]) in scenario.topology
            elif t == "access_at_least":
                if LEVELS[p["level"]] > 0:
                    pres.append(("a", p["host"], LEVELS[p["level"]]))
            else:
                pres.append(("k", p["fact"]))
        if not ok:
            continue
        effs = []
        for e in a.effects:
            if e["type"] == "set_access":
                effs += [("a", e["host"], r) for r in range(1, LEVELS[e["level"]] + 1)]
            else:
                effs.append(("k", e["fact"]))
        out.append((tuple(pres), tuple(effs), c))
    return out


def make_hmax(scenario, costs):
    """h_max heuristic (Bonet & Geffner 2001) for real-valued `costs`.

    Effects only add access or knowledge and every precondition is positive,
    so the delete relaxation keeps reachability exact; h_max(s) = cost of the
    most expensive single fact on the cheapest relaxed way to the goal. It is
    admissible and consistent, so A* with it returns the same optimal cost as
    Dijkstra; and h_max(s) = inf exactly when the goal is unreachable from s,
    which ends the search at once when a patch set blocks every path.
    """
    acts = _relaxed_actions(scenario, costs)
    goal = ("a", scenario.goal["host"], LEVELS[scenario.goal["level"]])
    cache = {}

    def h(state):
        key = state_key(state)
        if key in cache:
            return cache[key]
        cost = {("k", f): 0.0 for f in state.known}
        for host, lvl in state.access.items():
            for r in range(1, LEVELS[lvl] + 1):
                cost[("a", host, r)] = 0.0
        changed = True
        while changed:
            changed = False
            for pres, effs, c in acts:
                m = 0.0
                for p in pres:
                    v = cost.get(p)
                    if v is None:
                        break
                    if v > m:
                        m = v
                else:
                    n = m + c
                    for e in effs:
                        if n < cost.get(e, math.inf):
                            cost[e] = n
                            changed = True
        cache[key] = cost.get(goal, math.inf)
        return cache[key]
    return h


def risk(scenario, costs):
    """(P*, best path or None, search metrics) under real-valued `costs`.

    A* with `make_hmax`: same optimum as Dijkstra (tested), far fewer states;
    successors with h = inf cannot reach the goal and are dropped.
    """
    h = make_hmax(scenario, costs)
    init = initial_state(scenario)
    if h(init) == math.inf:
        return 0.0, None, {"nodes_expanded": 0, "edges_examined": 0}
    succ = weighted_successors(scenario, costs)
    path, metrics = astar(init, lambda s: [t for t in succ(s) if h(t[1]) != math.inf],
                          lambda s: is_goal(s, scenario.goal), h)
    if path is None:
        return 0.0, None, metrics
    return math.exp(-sum(costs[a] for a in path)), path, metrics


def risk_dijkstra(scenario, costs):
    """Reference implementation of `risk` with plain Dijkstra (used in tests)."""
    path, metrics = dijkstra(initial_state(scenario), weighted_successors(scenario, costs),
                             lambda s: is_goal(s, scenario.goal))
    if path is None:
        return 0.0, None, metrics
    return math.exp(-sum(costs[a] for a in path)), path, metrics


class RiskOracle:
    """P* of `scenario` after patching any set of units, with a cache.

    Policies and the evaluation ask for the same patch sets many times (every
    prefix of every order); the cache makes each distinct set cost one search.
    """

    def __init__(self, scenario, costs, unit_actions):
        self.scenario = scenario
        self.costs = costs
        self.unit_actions = unit_actions
        self._cache = {}
        self.searches = 0

    def units(self):
        return list(self.unit_actions)

    def evaluate(self, patched):
        """(P*, best path) after patching the units in `patched`."""
        key = frozenset(patched)
        if key not in self._cache:
            self.searches += 1
            p, path, _ = risk(patch(self.scenario, key, self.unit_actions), self.costs)
            self._cache[key] = (p, path)
        return self._cache[key]

    def __call__(self, patched):
        return self.evaluate(patched)[0]

    def units_on_path(self, path):
        """Units owning at least one action of `path`, sorted."""
        on = set(path or [])
        return [u for u, acts in self.unit_actions.items() if on.intersection(acts)]


def risk_curve(oracle, order, k_max):
    """[R(0), ..., R(K)]: P* after patching the first k units of `order`.

    If `order` is shorter than K the curve stays at its last value (nothing
    left to patch).
    """
    return [oracle(order[:k]) for k in range(k_max + 1)]


def curve_metrics(curve):
    """AUC (trapezoid over k, normalised by K * R(0)) and k_block."""
    r0, k_max = curve[0], len(curve) - 1
    area = sum((curve[k] + curve[k + 1]) / 2 for k in range(k_max))
    auc = area / (k_max * r0) if r0 > 0 and k_max > 0 else 0.0
    k_block = next((k for k, r in enumerate(curve) if r == 0), None)
    return {"auc": auc, "k_block": k_block}
