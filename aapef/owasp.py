"""OWASP Risk Rating Methodology on the attack graph (AAPEF v2 main risk model).

Risk of an asset = Likelihood x Impact, every factor on the OWASP 0-9 scale.

Likelihood of one attack step (an action that exploits a vulnerability) is
the mean of the 8 OWASP likelihood factors:

  threat agent (set by the organisation, one profile):
      skill, motive, opportunity, size
  vulnerability (filled from published data, see DEFAULT_MAPPING):
      ease of discovery   CVSS AV       N/A -> 9, L -> 7, P -> 3
      ease of exploit     KEV -> 9; else EPSS >= 0.1 -> 7;
                          else AC:L and UI:N -> 5; else 3
      awareness           9 (the CVE is published)
      intrusion detection set by the organisation per network zone
                          of the step's target host (default 8:
                          "logged without review")

Scans and structural steps (no vulnerability) do not limit the likelihood.

Likelihood of a path = that of its hardest step (min), because the attacker
must get through every step. Likelihood of an asset = that of its easiest
path (max over paths): a bottleneck ("widest") path problem. Effects only add
access or knowledge, so a path exists exactly when the goal is reachable in
the delete relaxation, and the max-min value is found by a label-setting
(generalised Dijkstra) pass over facts and actions: polynomial in the number
of actions, no state-space search. The pass also yields a witness plan (the
actions used); patching anything off the witness cannot change the asset's
likelihood, which keeps the context-greedy policy exact.

Impact of an asset: mean of the business-impact factors the organisation
gives (financial, reputation, non-compliance, privacy); without them, mean of
the technical factors (confidentiality, integrity, availability,
accountability; default 7 each = full compromise at admin).

Levels: score < 3 LOW, < 6 MEDIUM, else HIGH; the OWASP matrix combines the
likelihood and impact levels into Note / Low / Medium / High / Critical.

Defence measures (units), each removes a set of actions:
  patch   "<CVE>@<host>" (or the vulnerability slot of a CVE-less scenario),
          as defense.patch_units
  block   "block:<zone>><zone>:<service>": a firewall rule that drops one
          service between two zones; removes the remote exploit steps that
          cross it. Business flows listed in the configuration cannot be
          blocked (default: every flow from the Internet, i.e. the services
          the organisation publishes).
"""

import copy
import heapq
import json
import math
import re
from statistics import mean

from .cvss import CostModel, derive_vector, is_discovery
from .defense import patch_units, sensitive_hosts
from .prob import is_vulnerability
from .state import LEVELS

RISK_LEVELS = ("Note", "Low", "Medium", "High", "Critical")
MATRIX = {  # (impact level, likelihood level) -> overall risk
    ("HIGH", "LOW"): "Medium", ("HIGH", "MEDIUM"): "High", ("HIGH", "HIGH"): "Critical",
    ("MEDIUM", "LOW"): "Low", ("MEDIUM", "MEDIUM"): "Medium", ("MEDIUM", "HIGH"): "High",
    ("LOW", "LOW"): "Note", ("LOW", "MEDIUM"): "Low", ("LOW", "HIGH"): "Medium",
}
THREAT_FACTORS = ("skill", "motive", "opportunity", "size")
TECH_FACTORS = ("confidentiality", "integrity", "availability", "accountability")
BUSINESS_FACTORS = ("financial", "reputation", "non_compliance", "privacy")

DEFAULT_MAPPING = {
    "ease_of_discovery": {"N": 9, "A": 9, "L": 7, "P": 3},
    "ease_of_exploit": {"kev": 9, "epss_threshold": 0.1, "epss_high": 7,
                        "easy": 5, "otherwise": 3},
    "awareness": 9,
    "cia_to_technical": {"H": 7, "L": 2, "N": 0},
    "accountability": 7,
}

DEFAULT_CONFIG = {
    "organisation": "example",
    "threat_profile": {"name": "default", "skill": 6, "motive": 4, "opportunity": 7, "size": 9},
    "intrusion_detection": {"default": 8, "zones": {}},
    "zones": {},
    "assets": {},
    "default_technical_impact": {"confidentiality": 7, "integrity": 7,
                                 "availability": 7, "accountability": 7},
    "acceptable_risk": "Low",
    "business_flows": [["Internet", "*", "*"]],
    "mapping": DEFAULT_MAPPING,
}


# ------------------------------------------------------------ configuration --

def _merge(base, over):
    out = copy.deepcopy(base)
    for k, v in (over or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict) and k not in ("assets", "zones"):
            out[k] = _merge(out[k], v)
        else:
            out[k] = copy.deepcopy(v)
    return out


def _check_score(value, where):
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not 0 <= value <= 9:
        raise ValueError(f"{where}: OWASP factor must be a number in [0, 9], got {value!r}")


def make_config(over=None):
    """Defaults merged with the organisation's settings, validated."""
    cfg = _merge(DEFAULT_CONFIG, over)
    for f in THREAT_FACTORS:
        _check_score(cfg["threat_profile"].get(f), f"threat_profile.{f}")
    _check_score(cfg["intrusion_detection"]["default"], "intrusion_detection.default")
    for z, v in cfg["intrusion_detection"]["zones"].items():
        _check_score(v, f"intrusion_detection.zones.{z}")
    for f in TECH_FACTORS:
        _check_score(cfg["default_technical_impact"].get(f), f"default_technical_impact.{f}")
    for host, a in cfg["assets"].items():
        for group, names in (("technical", TECH_FACTORS), ("business", BUSINESS_FACTORS)):
            if group in a:
                for f in names:
                    _check_score(a[group].get(f), f"assets.{host}.{group}.{f}")
    if cfg["acceptable_risk"] not in RISK_LEVELS:
        raise ValueError(f"acceptable_risk must be one of {RISK_LEVELS}")
    for flow in cfg["business_flows"]:
        if not (isinstance(flow, list) and len(flow) == 3):
            raise ValueError(f"business_flows entries are [src zone, dst zone, service]: {flow!r}")
    return cfg


def load_config(path=None):
    if path is None:
        return make_config()
    with open(path, encoding="utf-8") as fh:
        return make_config(json.load(fh))


# ------------------------------------------------------------------ scoring --

def level3(score):
    """OWASP LOW / MEDIUM / HIGH of a 0-9 score."""
    return "LOW" if score < 3 else "MEDIUM" if score < 6 else "HIGH"


def overall(likelihood, impact):
    """Overall risk level from the OWASP matrix; Note when there is no path."""
    if likelihood <= 0:
        return "Note"
    return MATRIX[(level3(impact), level3(likelihood))]


def at_most(level, limit):
    return RISK_LEVELS.index(level) <= RISK_LEVELS.index(limit)


def zone_of(host, cfg):
    """Zone of a host: configured, else 'Internet' for ATK, 'S<n>' for H<n>_<i>."""
    if host in cfg["zones"]:
        return cfg["zones"][host]
    if host == "ATK":
        return "Internet"
    m = re.fullmatch(r"H(\d+)_\d+", host)
    return f"S{m.group(1)}" if m else host


def _cia(vector_string):
    out = {}
    for part in (vector_string or "").split("/"):
        k, _, v = part.partition(":")
        if k in ("C", "I", "A"):
            out[k] = v
    return out


def _target(action):
    return next(e["host"] for e in action["effects"] if e["type"] == "set_access")


def step_factors(action, cfg, snapshot=None):
    """The 8 likelihood factors of one raw action, or None (scan / structural)."""
    if is_discovery(action) or not (action.get("cve") or is_vulnerability(action)):
        return None
    mp = cfg["mapping"]
    kev, epss_v = False, None
    if action.get("cve"):
        if snapshot is None or action["cve"] not in snapshot.cves:
            raise ValueError(f"action {action['id']!r}: {action['cve']} needs the snapshot")
        rec = snapshot.cves[action["cve"]]
        if rec.vector is None:
            raise ValueError(f"action {action['id']!r}: {action['cve']} has no CVSS vector")
        vec, kev, epss_v = rec.vector, rec.kev, rec.epss
    else:
        vec = derive_vector(action, CostModel())
    ee = mp["ease_of_exploit"]
    if kev:
        exploit = ee["kev"]
    elif epss_v is not None and epss_v >= ee["epss_threshold"]:
        exploit = ee["epss_high"]
    elif vec.get("AC") == "L" and vec.get("UI") == "N":
        exploit = ee["easy"]
    else:
        exploit = ee["otherwise"]
    tp = cfg["threat_profile"]
    zone = zone_of(_target(action), cfg)
    ids = cfg["intrusion_detection"]
    return {"skill": tp["skill"], "motive": tp["motive"], "opportunity": tp["opportunity"],
            "size": tp["size"], "ease_of_discovery": mp["ease_of_discovery"][vec["AV"]],
            "ease_of_exploit": exploit, "awareness": mp["awareness"],
            "intrusion_detection": ids["zones"].get(zone, ids["default"])}


def step_likelihood(action, cfg, snapshot=None):
    f = step_factors(action, cfg, snapshot)
    return None if f is None else mean(f.values())


def asset_impact(host, cfg):
    """(impact score, basis) of compromising `host` at admin."""
    a = cfg["assets"].get(host, {})
    if "business" in a:
        return mean(a["business"][f] for f in BUSINESS_FACTORS), "business"
    tech = a.get("technical", cfg["default_technical_impact"])
    return mean(tech[f] for f in TECH_FACTORS), "technical"


def vuln_impact(action, cfg, snapshot=None):
    """Impact of one vulnerability on its own host (for the per-vulnerability policy)."""
    host = _target(action)
    a = cfg["assets"].get(host, {})
    if "business" in a:
        return mean(a["business"][f] for f in BUSINESS_FACTORS)
    rec = snapshot.cves.get(action.get("cve")) if (snapshot and action.get("cve")) else None
    cia = _cia(rec.vector_string) if rec else {}
    if len(cia) == 3:
        m = cfg["mapping"]["cia_to_technical"]
        return mean([m[cia["C"]], m[cia["I"]], m[cia["A"]], cfg["mapping"]["accountability"]])
    return mean(cfg["default_technical_impact"][f] for f in TECH_FACTORS)


def asset_hosts(data, cfg):
    """Configured assets, else the scenario's sensitive hosts."""
    hosts = {h["id"] for h in data["hosts"]}
    if cfg["assets"]:
        missing = sorted(set(cfg["assets"]) - hosts)
        if missing:
            raise ValueError(f"assets not in the scenario: {missing}")
        return sorted(cfg["assets"])
    return sensitive_hosts(data)


# ------------------------------------------------------------------ measures --

_SERVICE = re.compile(r"\(([^()]+)\) from ")


def action_service(action):
    """Service an exploit uses: the 'service' field, else from the converter's name."""
    if action.get("service"):
        return action["service"]
    m = _SERVICE.search(action.get("name", ""))
    return m.group(1) if m else "*"


def _flow_match(flow, src, dst, service):
    return all(f == "*" or f == v for f, v in zip(flow, (src, dst, service)))


def block_units(data, cfg):
    """{"block:<src>><dst>:<service>": [action ids]} for blockable cross-zone flows."""
    units = {}
    for a in data["actions"]:
        if is_discovery(a) or not (a.get("cve") or is_vulnerability(a)):
            continue
        dst = zone_of(_target(a), cfg)
        service = action_service(a)
        for p in a["preconditions"]:
            if p["type"] != "reachable":
                continue
            src = zone_of(p["from"], cfg)
            if src == dst or any(_flow_match(f, src, dst, service) for f in cfg["business_flows"]):
                continue
            units.setdefault(f"block:{src}>{dst}:{service}", []).append(a["id"])
    return {k: sorted(set(v)) for k, v in sorted(units.items())}


def measure_units(data, cfg, kinds=("patch",)):
    out = {}
    if "patch" in kinds:
        out.update(patch_units(data))
    if "block" in kinds:
        out.update(block_units(data, cfg))
    return out


# ------------------------------------------------------- bottleneck oracle --

class OwaspOracle:
    """Asset risks after any set of measures, with a cache.

    Same interface as defense.RiskOracle (units, evaluate, __call__,
    units_on_path, searches), so policies.context_greedy and policies.optimal
    run on it unchanged. The value is the network risk
    R = sum over assets of likelihood x impact (0 when nothing is reachable).
    """

    def __init__(self, data, cfg, snapshot=None, kinds=("patch",)):
        self.data, self.cfg = data, cfg
        self.unit_actions = measure_units(data, cfg, kinds)
        self.assets = asset_hosts(data, cfg)
        self.impact = {h: asset_impact(h, cfg) for h in self.assets}
        env = set(data.get("env_facts", []))
        topo = {tuple(e) for e in data["topology"]}
        self.step_L = {}
        self.acts = []   # (id, pres, effs, L)
        for a in data["actions"]:
            L = step_likelihood(a, cfg, snapshot)
            self.step_L[a["id"]] = L
            pres, ok = [], True
            for p in a["preconditions"]:
                t = p["type"]
                if t == "env_fact":
                    ok = ok and p["fact"] in env
                elif t == "reachable":
                    ok = ok and (p["from"], p["to"]) in topo
                elif t == "access_at_least":
                    if LEVELS[p["level"]] > 0:
                        pres.append(("a", p["host"], LEVELS[p["level"]]))
                else:
                    pres.append(("k", p["fact"]))
            if not ok:
                continue
            effs = []
            for e in a["effects"]:
                if e["type"] == "set_access":
                    effs += [("a", e["host"], r) for r in range(1, LEVELS[e["level"]] + 1)]
                else:
                    effs.append(("k", e["fact"]))
            self.acts.append((a["id"], tuple(dict.fromkeys(pres)), tuple(effs),
                              math.inf if L is None else L))
        init = data["initial_state"]
        self.init_facts = {("k", f) for f in init.get("known", [])}
        for host, lvl in init["access"].items():
            self.init_facts |= {("a", host, r) for r in range(1, LEVELS[lvl] + 1)}
        self._cache = {}
        self.searches = 0

    def units(self):
        return list(self.unit_actions)

    def _bottleneck(self, removed):
        """{fact: value}, {fact: achiever index}, fire order of actions."""
        val, best, achiever, order = {}, {}, {}, {}
        watch, remaining = {}, []
        heap, tick = [], 0
        for f in self.init_facts:
            best[f] = math.inf
            heap.append((-math.inf, tick, f))
            tick += 1
        live = []
        for i, (aid, pres, effs, L) in enumerate(self.acts):
            remaining.append(len(pres))
            if aid in removed:
                continue
            live.append(i)
            for p in pres:
                watch.setdefault(p, []).append(i)

        def fire(i):
            nonlocal tick
            _aid, pres, effs, L = self.acts[i]
            v = min([L] + [val[p] for p in pres])
            order[i] = len(order)
            for e in effs:
                if e not in val and v > best.get(e, -1):
                    best[e], achiever[e] = v, i
                    heapq.heappush(heap, (-v, tick, e))
                    tick += 1
        for i in live:
            if remaining[i] == 0:
                fire(i)
        heapq.heapify(heap)
        while heap:
            negv, _t, f = heapq.heappop(heap)
            if f in val:
                continue
            val[f] = -negv
            for i in watch.get(f, ()):
                remaining[i] -= 1
                if remaining[i] == 0:
                    fire(i)
        return val, achiever, order

    def _witness(self, fact, achiever, order):
        need, seen, stack = set(), set(), [fact]
        while stack:
            f = stack.pop()
            if f in seen or f in self.init_facts:
                continue
            seen.add(f)
            i = achiever[f]
            if i not in need:
                need.add(i)
                stack.extend(self.acts[i][1])
        return [self.acts[i][0] for i in sorted(need, key=order.get)]

    def assess(self, patched):
        """{asset: {likelihood, impact, score, level, path}} after `patched`."""
        key = frozenset(patched)
        if key not in self._cache:
            removed = set()
            for u in key:
                if u not in self.unit_actions:
                    raise KeyError(f"unknown measure {u!r}")
                removed.update(self.unit_actions[u])
            self.searches += 1
            val, achiever, order = self._bottleneck(removed)
            out = {}
            for h in self.assets:
                goal = ("a", h, LEVELS["admin"])
                L = val.get(goal, 0.0)
                if L == math.inf:      # held from the start: no vulnerability on the way
                    L = 9.0
                I, basis = self.impact[h]
                path = self._witness(goal, achiever, order) if goal in val else None
                out[h] = {"likelihood": L, "impact": I, "impact_basis": basis,
                          "score": L * I, "level": overall(L, I), "path": path}
            self._cache[key] = out
        return self._cache[key]

    def evaluate(self, patched):
        res = self.assess(patched)
        value = sum(r["score"] for r in res.values())
        path = []
        for h in self.assets:
            for a in res[h]["path"] or []:
                if a not in path:
                    path.append(a)
        return value, (path if value > 0 else None)

    def __call__(self, patched):
        return self.evaluate(patched)[0]

    def accepted(self, patched):
        """True when every asset is at or below the acceptable risk level."""
        limit = self.cfg["acceptable_risk"]
        return all(at_most(r["level"], limit) for r in self.assess(patched).values())

    def units_on_path(self, path):
        on = set(path or [])
        return [u for u, acts in self.unit_actions.items() if on.intersection(acts)]


# ----------------------------------------------------------------- policies --

def greedy(oracle, k_max, lookahead=True):
    """Context policy: each step takes the measure that lowers R the most.

    Only measures on the current witness paths are tried (exact, see the
    module docstring). The OWASP scale is coarse, so often no single measure
    lowers R (another path has the same hardest step); with `lookahead` the
    tie is then broken by the best pair of measures (second one taken from the
    witness after the first). Ties left over go to the smallest unit id.
    """
    chosen = []
    while len(chosen) < k_max:
        v, path = oracle.evaluate(chosen)
        if v == 0:
            break
        cands = [u for u in oracle.units_on_path(path) if u not in chosen]
        if not cands:
            break
        scored = sorted((oracle(chosen + [u]), u) for u in cands)
        if scored[0][0] < v or not lookahead or len(chosen) + 1 == k_max:
            chosen.append(scored[0][1])
            continue
        best = None
        for _, u in scored:
            _, p2 = oracle.evaluate(chosen + [u])
            for w in oracle.units_on_path(p2):
                if w in chosen or w == u:
                    continue
                r = oracle(chosen + [u, w])
                if best is None or (r, u) < best:
                    best = (r, u)
        chosen.append(best[1] if best else scored[0][1])
    return chosen


def until_accepted(oracle, max_measures, lookahead=True):
    """Greedy order cut at the first prefix that meets the acceptance criterion."""
    order = greedy(oracle, max_measures, lookahead)
    for k in range(len(order) + 1):
        if oracle.accepted(order[:k]):
            return order[:k], True
    return order, False


def per_vulnerability(data, unit_actions, cfg, snapshot=None):
    """OWASP rating of each vulnerability on its own host, highest risk first.

    What an organisation does when it rates every finding with OWASP and
    ignores where it sits: risk = step likelihood x impact on that host.
    """
    by_id = {a["id"]: a for a in data["actions"]}
    score = {}
    for u, acts in unit_actions.items():
        vals = []
        for aid in acts:
            a = by_id[aid]
            L = step_likelihood(a, cfg, snapshot)
            if L is not None:
                vals.append(L * vuln_impact(a, cfg, snapshot))
        score[u] = max(vals) if vals else 0.0
    return sorted(unit_actions, key=lambda u: (-score[u], u))
