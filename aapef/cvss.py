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
Alternatively an action can name a real vulnerability with `cve`; its vector is
then taken from a catalog of NVD records (`load_catalog`), including Scope.
Actions that only learn facts (no `set_access` effect) are information
gathering, which CVSS does not score; they get the fixed probability
`discovery_p`.

Metric weights are the CVSS v3.1 values; only PR depends on Scope. Vectors
without an S metric are treated as Scope Unchanged.
"""

import copy
import json
import math
import re
from dataclasses import dataclass

AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
AC = {"L": 0.77, "H": 0.44}
PR = {"N": 0.85, "L": 0.62, "H": 0.27}          # Scope Unchanged
PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}   # Scope Changed
UI = {"N": 0.85, "R": 0.62}
SCOPE = {"U": "unchanged", "C": "changed"}
REQUIRED = ("AV", "AC", "PR", "UI")             # S is optional, default U
METRICS = {"AV": AV, "AC": AC, "PR": PR, "UI": UI, "S": SCOPE}

CVE_ID = re.compile(r"^CVE-\d{4}-\d{4,}$")

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
        missing = [k for k in REQUIRED if k not in vec]
        if missing:
            return f"missing metric(s) {missing}"
    return None


def exploitability(vec):
    """CVSS v3.1 Exploitability sub score of a full vector (S defaults to U)."""
    pr = (PR_CHANGED if vec.get("S", "U") == "C" else PR)[vec["PR"]]
    return 8.22 * AV[vec["AV"]] * AC[vec["AC"]] * pr * UI[vec["UI"]]


def parse_vector_string(text):
    """Parse 'CVSS:3.x/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' into a vector dict.

    Only the exploitability metrics (AV, AC, PR, UI, S) are kept; the impact
    metrics (C, I, A) do not enter the Exploitability sub score.
    """
    parts = text.split("/") if isinstance(text, str) else []
    if not parts or parts[0] not in ("CVSS:3.0", "CVSS:3.1"):
        raise ValueError(f"not a CVSS v3 vector string: {text!r}")
    vec = {}
    for part in parts[1:]:
        key, _, value = part.partition(":")
        if key in METRICS:
            vec[key] = value
    err = vector_error(vec)
    if err:
        raise ValueError(f"{text!r}: {err}")
    return vec


def load_catalog(path):
    """Load a CVE catalog (plan §9.3).

    Two shapes are accepted: {"cves": [{"id": "CVE-...", "vector": ...}, ...]}
    (the shape scen_gen.py also reads) and {"entries": {"CVE-...": {...}}}.
    Each entry keeps its provenance fields; `parsed` holds the vector dict.
    """
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    entries = data.get("entries") if isinstance(data, dict) else None
    if entries is None and isinstance(data, dict) and isinstance(data.get("cves"), list):
        entries = {}
        for rec in data["cves"]:
            cid = rec.get("id") if isinstance(rec, dict) else None
            if cid in entries:
                raise ValueError(f"{path}: duplicate CVE id {cid!r}")
            entries[cid] = rec
    if not isinstance(entries, dict) or not entries:
        raise ValueError(f"{path}: catalog needs a non-empty 'cves' list or 'entries' object")
    catalog = {}
    for cve, entry in entries.items():
        if not isinstance(cve, str) or not CVE_ID.match(cve):
            raise ValueError(f"{path}: bad CVE id {cve!r}")
        if not isinstance(entry, dict) or "vector" not in entry:
            raise ValueError(f"{path}: {cve} needs a 'vector' string")
        catalog[cve] = {**entry, "parsed": parse_vector_string(entry["vector"])}
    return catalog


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


def recost_scenario(data, model, catalog=None):
    """Return a deep copy of scenario dict `data` with CVSS-derived costs.

    Vector sources, per action:
      - `cve` (needs `catalog`): the NVD vector recorded for that CVE;
      - otherwise derived from structure, plus optional `cvss_override`.
    Re-running on its own output gives the same result: only `cve` and
    `cvss_override` are read as input; `cost`, `cvss` and `cost_basis` are
    always rewritten.
    """
    model.validate()
    out = copy.deepcopy(data)
    used_cves = set()
    for action in out["actions"]:
        aid = action.get("id")
        override = action.get("cvss_override")
        cve = action.get("cve")
        if override is not None:
            err = vector_error(override, partial=True)
            if err:
                raise ValueError(f"action {aid!r}: cvss_override {err}")
        action.pop("cvss", None)
        if cve is not None:
            if is_discovery(action):
                raise ValueError(
                    f"action {aid!r}: cve on an information-gathering action "
                    "(it has no set_access effect)")
            if override:
                raise ValueError(
                    f"action {aid!r}: use either cve or cvss_override, not both")
            if catalog is None:
                raise ValueError(
                    f"action {aid!r}: cve {cve} needs a CVE catalog "
                    "(pass --catalog, or run from the repo root so "
                    "scenarios/cve_catalog.json is found)")
            if cve not in catalog:
                raise ValueError(f"action {aid!r}: {cve} is not in the catalog")
            vec = dict(catalog[cve]["parsed"])
            action["cost_basis"] = "cve"
            action["cvss"] = vec
            action["cost"] = vector_cost(vec, model)
            used_cves.add(cve)
        elif is_discovery(action):
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
    if used_cves:
        out["cost_model"]["cves"] = sorted(used_cves)
    return out
