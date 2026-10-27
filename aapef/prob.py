"""Success-probability models and real-valued costs (MasterPlan §5.3).

Every action gets a success probability p from one model; its cost is -ln p as
a float, never rounded, so that the cost of a path is exactly -ln of the
probability that all its steps succeed (steps independent). The integer `cost`
field of the scenario JSON is not read or changed here, so the validator and
the earlier regression results stay as they are.

Which rule gives p, per action (first match wins):
  1. no `set_access` effect (scan / information gathering): p = discovery_p
  2. `cve` field: from the snapshot record of that CVE, by model
       cvss    p = Exploitability(vector) / p_norm
       epss    p = epss
       kev     p = p_kev if the CVE is in KEV, else epss
       native  p = the action's `prob`
  3. an `env_fact` precondition or a `cvss_override` (a vulnerability without a
     CVE, e.g. a converted NASim exploit):
       cvss    p = Exploitability(vector derived from structure) / p_norm,
               the same vector `aapef recost` uses (cvss.derive_vector)
       native  p = the action's `prob`
       epss, kev: error, there is no CVE to look up
  4. otherwise (structural step that needs no vulnerability, e.g. the virtual
     `capture_all` of converted NASim scenarios): p = 1, cost 0

`native` reads a `prob` field in [0, 1] on each scored action: NASim's own
success probability, which the converter has to carry over for group N1.
p = 0 gives cost inf: the action can never succeed and is not an edge.
"""

import math
from dataclasses import dataclass

from .cvss import CostModel, derive_vector, exploitability, is_discovery
from .state import successors

MODELS = ("cvss", "epss", "kev", "native")


@dataclass(frozen=True)
class ProbModel:
    """Published parameters of one probability model (reported with results)."""

    name: str
    p_kev: float = 0.9          # M-KEV: p of a CVE listed in KEV [proposed value]
    discovery_p: float = 0.9    # rule 1; same value as cvss.CostModel
    p_norm: float = 10.0        # M-CVSS: p = E / p_norm, as in cvss.CostModel

    def validate(self):
        if self.name not in MODELS:
            raise ValueError(f"unknown probability model {self.name!r}; use one of {MODELS}")
        if not 0 < self.p_kev <= 1:
            raise ValueError("p_kev must be in (0, 1]")
        if not 0 < self.discovery_p <= 1:
            raise ValueError("discovery_p must be in (0, 1]")
        if self.p_norm < exploitability({"AV": "N", "AC": "L", "PR": "N", "UI": "N"}):
            raise ValueError("p_norm too small: p would exceed 1")

    def describe(self):
        out = {"name": self.name, "discovery_p": self.discovery_p}
        if self.name == "cvss":
            out["p_norm"] = self.p_norm
        if self.name == "kev":
            out["p_kev"] = self.p_kev
        return out


def _native(action):
    p = action.get("prob")
    if isinstance(p, bool) or not isinstance(p, (int, float)) or not 0 <= p <= 1:
        raise ValueError(f"action {action.get('id')!r}: model 'native' needs a "
                         f"'prob' in [0, 1], got {p!r}")
    return float(p)


def is_vulnerability(action):
    """Rule 3: the action exploits a vulnerability that has no CVE id."""
    return ("cvss_override" in action
            or any(p["type"] == "env_fact" for p in action.get("preconditions", [])))


def action_probability(action, model, snapshot=None):
    """(p, basis) of one raw action dict under `model`; see the module docstring."""
    aid = action.get("id")
    if is_discovery(action):
        return model.discovery_p, "discovery"
    cve = action.get("cve")
    if cve is not None:
        if model.name == "native":
            return _native(action), "native"
        if snapshot is None:
            raise ValueError(f"action {aid!r}: cve {cve} needs a snapshot")
        rec = snapshot.cves.get(cve)
        if rec is None:
            raise ValueError(f"action {aid!r}: {cve} is not in snapshot {snapshot.id}")
        if model.name == "cvss":
            if rec.vector is None:
                raise ValueError(f"action {aid!r}: {cve} has no CVSS v3 vector in "
                                 f"snapshot {snapshot.id}")
            return rec.exploitability / model.p_norm, "cve-cvss"
        if model.name == "kev" and rec.kev:
            return model.p_kev, "cve-kev"
        if rec.epss is None:
            raise ValueError(f"action {aid!r}: {cve} has no EPSS score in "
                             f"snapshot {snapshot.id}")
        return rec.epss, "cve-epss"
    if is_vulnerability(action):
        if model.name == "native":
            return _native(action), "native"
        if model.name == "cvss":
            vec = derive_vector(action, CostModel())
            return exploitability(vec) / model.p_norm, "derived-cvss"
        raise ValueError(f"action {aid!r}: model {model.name!r} needs a cve on "
                         "every exploit action")
    return 1.0, "structural"


def probability_table(data, model, snapshot=None):
    """{action id: (p, basis)} for scenario dict `data`."""
    model.validate()
    return {a["id"]: action_probability(a, model, snapshot) for a in data["actions"]}


def cost_from_p(p):
    """-ln p as a float; inf when p == 0 (the action never succeeds)."""
    if not 0 <= p <= 1:
        raise ValueError(f"probability out of range: {p}")
    return math.inf if p == 0 else -math.log(p)


def cost_table(data, model, snapshot=None):
    """{action id: -ln p} for scenario dict `data`."""
    return {aid: cost_from_p(p) for aid, (p, _) in
            probability_table(data, model, snapshot).items()}


def weighted_successors(scenario, costs):
    """succ_fn for the search algorithms that uses `costs` instead of `Action.cost`.

    Transitions come from state.successors unchanged; actions with cost inf
    (p == 0) are dropped because they can never be taken.
    """
    def succ(state):
        out = []
        for action, nxt, _ in successors(state, scenario):
            c = costs[action.id]
            if c != math.inf:
                out.append((action, nxt, c))
        return out
    return succ
