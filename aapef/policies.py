"""Patch prioritisation policies (ThietKe_ThiNghiem §5, MasterPlan §7.3).

Each policy returns an order of patch units; R(k) patches the first k. Only
`context_greedy` and `optimal` see the network and the goal (through a
`RiskOracle`); the score policies see one number per unit, which is exactly
the difference the experiment measures. Ties are always broken by unit id,
ascending, so every order is deterministic.

Score of a unit with several actions (the same CVE exploited from several
source hosts) = the maximum over its actions.
"""

import itertools
import random

from .prob import action_probability


def _by_score(units, score):
    """Units by score descending, then by id."""
    return sorted(units, key=lambda u: (-score[u], u))


def _unit_actions_raw(data, unit_actions):
    by_id = {a["id"]: a for a in data["actions"]}
    return {u: [by_id[a] for a in acts] for u, acts in unit_actions.items()}


def by_probability(data, unit_actions, model, snapshot=None):
    """Highest success probability first (group N: NASim prob or derived CVSS)."""
    raw = _unit_actions_raw(data, unit_actions)
    score = {u: max(action_probability(a, model, snapshot)[0] for a in acts)
             for u, acts in raw.items()}
    return _by_score(unit_actions, score)


def _cve_records(data, unit_actions, snapshot):
    raw = _unit_actions_raw(data, unit_actions)
    out = {}
    for u, acts in raw.items():
        cves = {a.get("cve") for a in acts}
        if len(cves) != 1 or None in cves:
            raise ValueError(f"unit {u!r}: score policies need one cve per unit")
        cve = cves.pop()
        if cve not in snapshot.cves:
            raise ValueError(f"unit {u!r}: {cve} is not in snapshot {snapshot.id}")
        out[u] = snapshot.cves[cve]
    return out


def _require(value, what, u):
    if value is None:
        raise ValueError(f"unit {u!r}: no {what} in the snapshot")
    return value


def cvss_base(data, unit_actions, snapshot):
    recs = _cve_records(data, unit_actions, snapshot)
    return _by_score(unit_actions, {u: _require(r.base_score, "base score", u)
                                    for u, r in recs.items()})


def cvss_exploit(data, unit_actions, snapshot):
    recs = _cve_records(data, unit_actions, snapshot)
    return _by_score(unit_actions, {u: _require(r.exploitability, "CVSS vector", u)
                                    for u, r in recs.items()})


def epss(data, unit_actions, snapshot):
    recs = _cve_records(data, unit_actions, snapshot)
    return _by_score(unit_actions, {u: _require(r.epss, "EPSS score", u)
                                    for u, r in recs.items()})


def kev_first(data, unit_actions, snapshot):
    """KEV-listed units first, each group by EPSS descending."""
    recs = _cve_records(data, unit_actions, snapshot)
    return sorted(unit_actions, key=lambda u: (not recs[u].kev,
                                              -_require(recs[u].epss, "EPSS score", u), u))


def random_order(unit_actions, seed):
    order = sorted(unit_actions)
    random.Random(seed).shuffle(order)
    return order


def context_greedy(oracle, k_max):
    """Each step patches the unit whose removal lowers P* the most.

    Only units on the current best path are evaluated: removing actions can
    never create a better path, so if the best path survives a patch, P* is
    unchanged. This is exact, not a heuristic. Stops early when P* = 0 (every
    further patch is equally useless); the order then has fewer than K units.
    """
    chosen = []
    for _ in range(k_max):
        p, path = oracle.evaluate(chosen)
        if p == 0:
            break
        best = None
        for u in oracle.units_on_path(path):
            if u in chosen:
                continue
            cand = oracle(chosen + [u])
            if best is None or cand < best[0]:   # units_on_path is sorted: ties -> id
                best = (cand, u)
        if best is None:
            break   # best path uses no patchable unit: nothing can lower P*
        chosen.append(best[1])
    return chosen


def optimal(oracle, k_max):
    """[(R*(k), best set)] for k = 0..K by exhaustive search; small networks only.

    The sets for different k need not be nested, so this is a curve of optima,
    not an order. Ties: the first set in itertools.combinations order of the
    sorted unit ids. For k beyond the number of units every unit is already
    patched, so the entry for k = len(units) is repeated.
    """
    units = sorted(oracle.units())
    out = []
    for k in range(k_max + 1):
        if k > len(units):
            out.append(out[-1])
            continue
        best = None
        for combo in itertools.combinations(units, k):
            r = oracle(combo)
            if best is None or r < best[0]:
                best = (r, list(combo))
                if r == 0:
                    break
        out.append(best)
    return out
