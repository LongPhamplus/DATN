"""Action costs derived from CVSS v3.1 (plan §9.2-9.3).

Instead of hand-typed costs, each action's cost is computed from a CVSS v3.1
vector with a published formula:

    Exploitability E = 8.22 * AV * AC * PR * UI          (FIRST, spec §7.1)
    p                = E / p_norm                        (success probability)
    cost             = round(scale * -ln(p))             (non-negative integer)

-ln turns a product of success probabilities into a sum, so the total cost of a
path is about -scale * ln(P(whole path succeeds)) when steps are independent.
Dijkstra / A* therefore find the path most likely to succeed.

The vector is derived from the action's own structure (plan §9.3):
    AV = N if the action has a `reachable` precondition, else L
    PR = highest `access_at_least` level required (none->N, user->L, admin->H)
    AC, UI = published defaults (CostModel.default_ac / default_ui)
and can be overridden per action with `cvss_override` (a partial vector).
Actions that only learn facts (no `set_access` effect) are information
gathering, which CVSS does not score; they get the fixed probability
`discovery_p`.

Metric weights are the CVSS v3.1 values for Scope Unchanged.
"""

import copy
import math
from dataclasses import dataclass

AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
AC = {"L": 0.77, "H": 0.44}
PR = {"N": 0.85, "L": 0.62, "H": 0.27}   # Scope Unchanged
UI = {"N": 0.85, "R": 0.62}
METRICS = {"AV": AV, "AC": AC, "PR": PR, "UI": UI}

# Largest possible Exploitability: AV:N / AC:L / PR:N / UI:N.
MAX_EXPLOITABILITY = 8.22 * AV["N"] * AC["L"] * PR["N"] * UI["N"]

LEVEL_TO_PR = {"none": "N", "user": "L", "admin": "H"}
_LEVEL_RANK = {"none": 0, "user": 1, "admin": 2}

MODEL_NAME = "cvss-3.1-exploitability-neglog"


@dataclass(frozen=True)
class CostModel:
    """Published assumptions of the cost model (all reported in the output)."""

    scale: int = 10            # cost = round(scale * -ln p)
    p_norm: float = 10.0       # p = E / p_norm
    discovery_p: float = 0.9   # success probability of information gathering
    default_ac: str = "L"
    default_ui: str = "N"

    def validate(self):
        if not (isinstance(self.scale, int) and self.scale > 0):
            raise ValueError("scale must be a positive integer")
        if self.p_norm < MAX_EXPLOITABILITY:
            raise ValueError(
                f"p_norm must be >= {MAX_EXPLOITABILITY:.3f} so that p <= 1")
        if not 0 < self.discovery_p <= 1:
            raise ValueError("discovery_p must be in (0, 1]")
        if self.default_ac not in AC:
            raise ValueError(f"default_ac must be one of {sorted(AC)}")
        if self.default_ui not in UI:
            raise ValueError(f"default_ui must be one of {sorted(UI)}")

    def describe(self):
        return {"name": MODEL_NAME, "scale": self.scale, "p_norm": self.p_norm,
                "discovery_p": self.discovery_p, "default_ac": self.default_ac,
                "default_ui": self.default_ui, "scope": "unchanged"}


def vector_error(vec, partial=False):
    """Return a message if `vec` is not a valid (partial) vector, else None."""
    if not isinstance(vec, dict):
        return "must be an object"
    for key, value in vec.items():
        if key not in METRICS:
            return f"unknown metric {key!r}"
        if not isinstance(value, str) or value not in METRICS[key]:
            return f"invalid value {value!r} for {key}"
    if not partial:
        missing = [k for k in METRICS if k not in vec]
        if missing:
            return f"missing metric(s) {missing}"
    return None


def exploitability(vec):
    """CVSS v3.1 Exploitability sub score of a full vector."""
    return 8.22 * AV[vec["AV"]] * AC[vec["AC"]] * PR[vec["PR"]] * UI[vec["UI"]]


def cost_from_probability(p, model):
    """round(scale * -ln p); 0 when p == 1."""
    if not 0 < p <= 1:
        raise ValueError(f"probability out of range: {p}")
    return int(math.floor(model.scale * -math.log(p) + 0.5))


def vector_cost(vec, model):
    """Cost of a full CVSS vector under `model`."""
    return cost_from_probability(exploitability(vec) / model.p_norm, model)


def is_discovery(action):
    """True if the action only learns facts (no access is gained)."""
    return not any(e["type"] == "set_access" for e in action["effects"])


def derive_vector(action, model):
    """Vector from the action's structure plus its `cvss_override`, if any."""
    pres = action.get("preconditions", [])
    has_reach = any(p["type"] == "reachable" for p in pres)
    levels = [p["level"] for p in pres if p["type"] == "access_at_least"]
    top = max(levels, key=lambda lv: _LEVEL_RANK[lv]) if levels else "none"
    vec = {"AV": "N" if has_reach else "L", "AC": model.default_ac,
           "PR": LEVEL_TO_PR[top], "UI": model.default_ui}
    vec.update(action.get("cvss_override", {}))
    return vec


def recost_scenario(data, model):
    """Return a deep copy of scenario dict `data` with CVSS-derived costs.

    Re-running on its own output gives the same result: only `cvss_override`
    is read as input; `cost`, `cvss` and `cost_basis` are always rewritten.
    """
    model.validate()
    out = copy.deepcopy(data)
    for action in out["actions"]:
        aid = action.get("id")
        override = action.get("cvss_override")
        if override is not None:
            err = vector_error(override, partial=True)
            if err:
                raise ValueError(f"action {aid!r}: cvss_override {err}")
        action.pop("cvss", None)
        if is_discovery(action):
            if override:
                raise ValueError(
                    f"action {aid!r}: cvss_override on an information-gathering "
                    "action (it has no set_access effect)")
            action["cost_basis"] = "discovery"
            action["cost"] = cost_from_probability(model.discovery_p, model)
        else:
            vec = derive_vector(action, model)
            action["cost_basis"] = "cvss"
            action["cvss"] = vec
            action["cost"] = vector_cost(vec, model)
    out["cost_model"] = model.describe()
    return out
