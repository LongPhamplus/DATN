"""Scenario loading and validation (plan §6, §11.2).

One scenario is one JSON file holding hosts, topology, env_facts, actions,
initial_state and goal. Validation is a handful of explicit checks that raise
`ScenarioError` with a clear message — no schema framework (Simplicity First).
"""

import json
from dataclasses import dataclass

from .cvss import vector_error
from .state import LEVELS


class ScenarioError(ValueError):
    """Raised when a scenario file is malformed or inconsistent."""


@dataclass
class Action:
    id: str
    name: str
    preconditions: list  # list of dicts, see plan §6.2
    cost: int
    effects: list        # list of dicts
    evidence: list       # optional, simulation does not require it in the MVP


@dataclass
class Scenario:
    scenario_id: str
    hosts: list            # raw host dicts (descriptive metadata)
    host_ids: set
    topology: set          # set of (from, to) tuples
    env_facts: set         # set of fact strings (single source of truth)
    initial_access: dict   # host_id -> level
    initial_known: set     # set of fact strings
    actions: list          # list[Action]
    goal: dict

    def action_by_id(self, action_id):
        for a in self.actions:
            if a.id == action_id:
                return a
        raise KeyError(f"No action with id {action_id!r}")


# --- validation helpers ------------------------------------------------------

def _require(cond, msg):
    if not cond:
        raise ScenarioError(msg)


def _valid_level(level):
    return isinstance(level, str) and level in LEVELS


def _validate_precondition(pre, host_ids, where):
    _require(isinstance(pre, dict) and "type" in pre,
             f"{where}: precondition must be an object with a 'type'")
    t = pre["type"]
    if t == "access_at_least":
        _require(pre.get("host") in host_ids,
                 f"{where}: access_at_least references unknown host {pre.get('host')!r}")
        _require(_valid_level(pre.get("level")),
                 f"{where}: access_at_least has invalid level {pre.get('level')!r}")
    elif t == "known":
        _require(isinstance(pre.get("fact"), str),
                 f"{where}: known precondition needs a string 'fact'")
    elif t == "env_fact":
        _require(isinstance(pre.get("fact"), str),
                 f"{where}: env_fact precondition needs a string 'fact'")
    elif t == "reachable":
        _require(pre.get("from") in host_ids and pre.get("to") in host_ids,
                 f"{where}: reachable references unknown host(s)")
    else:
        raise ScenarioError(f"{where}: unknown precondition type {t!r}")


def _validate_effect(eff, host_ids, where):
    _require(isinstance(eff, dict) and "type" in eff,
             f"{where}: effect must be an object with a 'type'")
    t = eff["type"]
    if t == "set_access":
        _require(eff.get("host") in host_ids,
                 f"{where}: set_access references unknown host {eff.get('host')!r}")
        _require(_valid_level(eff.get("level")),
                 f"{where}: set_access has invalid level {eff.get('level')!r}")
    elif t == "learn":
        _require(isinstance(eff.get("fact"), str),
                 f"{where}: learn effect needs a string 'fact'")
    else:
        raise ScenarioError(f"{where}: unknown effect type {t!r}")


# --- build / load ------------------------------------------------------------

def build_scenario(data):
    """Validate a parsed scenario dict and return a `Scenario`.

    Raises `ScenarioError` on any inconsistency. Does NOT silently normalize
    input — malformed data is reported, not patched (plan §4.1).
    """
    _require(isinstance(data, dict), "scenario must be a JSON object")
    for key in ("scenario_id", "hosts", "actions", "initial_state", "goal"):
        _require(key in data, f"scenario missing required key {key!r}")

    # hosts
    hosts = data["hosts"]
    _require(isinstance(hosts, list) and hosts, "hosts must be a non-empty list")
    host_ids = set()
    for h in hosts:
        _require(isinstance(h, dict) and "id" in h, "each host needs an 'id'")
        hid = h["id"]
        _require(hid not in host_ids, f"duplicate host id {hid!r}")
        host_ids.add(hid)

    # topology
    topology = set()
    for edge in data.get("topology", []):
        _require(isinstance(edge, (list, tuple)) and len(edge) == 2,
                 "each topology edge must be a [from, to] pair")
        src, dst = edge
        _require(src in host_ids and dst in host_ids,
                 f"topology edge references unknown host(s): {edge}")
        topology.add((src, dst))

    # env_facts
    env_facts = data.get("env_facts", [])
    _require(isinstance(env_facts, list), "env_facts must be a list")
    _require(all(isinstance(f, str) for f in env_facts),
             "every env_fact must be a string")
    env_facts = set(env_facts)

    # initial_state
    init = data["initial_state"]
    _require(isinstance(init, dict) and "access" in init,
             "initial_state must be an object with 'access'")
    access = init["access"]
    _require(isinstance(access, dict), "initial_state.access must be an object")
    # full access mapping: exactly the declared hosts, each with a valid level
    missing = host_ids - set(access)
    extra = set(access) - host_ids
    _require(not missing, f"initial_state.access is missing host(s): {sorted(missing)}")
    _require(not extra, f"initial_state.access has unknown host(s): {sorted(extra)}")
    for hid, level in access.items():
        _require(_valid_level(level),
                 f"initial_state.access[{hid!r}] has invalid level {level!r}")
    initial_access = dict(access)

    known = init.get("known", [])
    _require(isinstance(known, list) and all(isinstance(f, str) for f in known),
             "initial_state.known must be a list of strings")
    initial_known = set(known)

    # actions
    raw_actions = data["actions"]
    _require(isinstance(raw_actions, list) and raw_actions,
             "actions must be a non-empty list")
    actions = []
    seen_ids = set()
    for i, a in enumerate(raw_actions):
        where = f"action[{i}]"
        _require(isinstance(a, dict), f"{where} must be an object")
        aid = a.get("id")
        _require(isinstance(aid, str) and aid, f"{where} needs a string 'id'")
        _require(aid not in seen_ids, f"duplicate action id {aid!r}")
        seen_ids.add(aid)
        where = f"action {aid!r}"

        cost = a.get("cost")
        _require(isinstance(cost, int) and not isinstance(cost, bool) and cost >= 0,
                 f"{where}: cost must be a non-negative integer")

        # optional CVSS fields (plan §9.3): partial override in, full vector out
        for key, partial in (("cvss_override", True), ("cvss", False)):
            if key in a:
                err = vector_error(a[key], partial=partial)
                _require(err is None, f"{where}: {key} {err}")

        pres = a.get("preconditions", [])
        _require(isinstance(pres, list), f"{where}: preconditions must be a list")
        for p in pres:
            _validate_precondition(p, host_ids, where)

        effs = a.get("effects", [])
        _require(isinstance(effs, list) and effs,
                 f"{where}: effects must be a non-empty list")
        for e in effs:
            _validate_effect(e, host_ids, where)

        actions.append(Action(
            id=aid,
            name=a.get("name", aid),
            preconditions=pres,
            cost=cost,
            effects=effs,
            evidence=a.get("evidence", []),
        ))

    # goal
    goal = data["goal"]
    _require(isinstance(goal, dict) and goal.get("type") == "access_at_least",
             "goal must be an object with type 'access_at_least'")
    _require(goal.get("host") in host_ids,
             f"goal references unknown host {goal.get('host')!r}")
    _require(_valid_level(goal.get("level")),
             f"goal has invalid level {goal.get('level')!r}")

    return Scenario(
        scenario_id=data["scenario_id"],
        hosts=hosts,
        host_ids=host_ids,
        topology=topology,
        env_facts=env_facts,
        initial_access=initial_access,
        initial_known=initial_known,
        actions=actions,
        goal=goal,
    )


def load_scenario(path):
    """Read a scenario JSON file from `path` and validate it."""
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    return build_scenario(data)
