"""Tests for the snapshot loader, probability models and role rule (week 2).

Most tests build a tiny snapshot in tmp_path, so they need no network and no
downloaded data. Tests marked `real` read data/snapshots and are skipped when
no snapshot has been fetched.
"""

import hashlib
import json
import math
import os

import pytest

from aapef.cvss import CostModel, load_catalog, parse_vector_string, recost_scenario
from aapef.data import SnapshotError, load_snapshot
from aapef.prob import ProbModel, action_probability, cost_table, weighted_successors
from aapef.roles import role_from_vector
from aapef.scenario import load_scenario
from aapef.search import dijkstra
from aapef.state import initial_state, is_goal

ROOT = os.path.join(os.path.dirname(__file__), os.pardir)
SCEN_DIR = os.path.join(ROOT, "scenarios")
SNAP_DIR = os.path.join(ROOT, "data", "snapshots")

LOG4SHELL = "CVE-2021-44228"
PWNKIT = "CVE-2021-4034"
NOT_KEV = "CVE-2024-0001"


def _write_snapshot(root, name="2026-01-01", tamper=None):
    kev = {"catalogVersion": "test", "vulnerabilities": [
        {"cveID": LOG4SHELL, "dateAdded": "2021-12-10"},
        {"cveID": PWNKIT, "dateAdded": "2022-06-27"}]}
    nvd = {"records": {
        LOG4SHELL: {"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                    "base_score": 10.0, "vector_source": "nvd", "published": "2021-12-10"},
        PWNKIT: {"vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
                 "base_score": 7.8, "vector_source": "nvd", "published": "2022-01-28"},
        NOT_KEV: {"vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
                  "base_score": 8.8, "vector_source": "cna", "published": "2024-01-02"}}}
    epss = {"records": {LOG4SHELL: [0.99999, 1.0], PWNKIT: [0.94921, 0.99859],
                        NOT_KEV: [0.0123, 0.5]}}
    files = {}
    for kind, obj in (("kev", kev), ("nvd", nvd), ("epss", epss)):
        fname = f"{kind}_{name}.json"
        raw = json.dumps(obj).encode()
        (root / fname).write_bytes(raw)
        files[fname] = {"kind": kind, "sha256": hashlib.sha256(raw).hexdigest()}
    if tamper:
        (root / tamper).write_bytes((root / tamper).read_bytes() + b" ")
    (root / "MANIFEST.json").write_text(json.dumps(
        {"snapshots": {name: {"files": files}}}))
    return root


@pytest.fixture
def snap(tmp_path):
    return load_snapshot(str(_write_snapshot(tmp_path)))


# --- loader ------------------------------------------------------------------

def test_snapshot_loads_and_joins_sources(snap):
    rec = snap.cves[LOG4SHELL]
    assert rec.kev and rec.kev_added == "2021-12-10"
    assert rec.epss == 0.99999 and rec.base_score == 10.0
    assert rec.vector["S"] == "C"
    assert round(rec.exploitability, 1) == 3.9   # NVD exploitabilityScore
    assert not snap.cves[NOT_KEV].kev
    assert snap.id.startswith("2026-01-01:") and len(snap.id) == len("2026-01-01:") + 12


def test_snapshot_with_changed_file_is_refused(tmp_path):
    _write_snapshot(tmp_path, tamper="epss_2026-01-01.json")
    with pytest.raises(SnapshotError, match="SHA-256"):
        load_snapshot(str(tmp_path))


def test_snapshot_missing_or_unknown_is_refused(tmp_path):
    with pytest.raises(SnapshotError):
        load_snapshot(str(tmp_path))
    _write_snapshot(tmp_path)
    with pytest.raises(SnapshotError, match="not in manifest"):
        load_snapshot(str(tmp_path), name="1999-01-01")


def test_snapshot_id_changes_with_data(tmp_path):
    first = load_snapshot(str(_write_snapshot(tmp_path))).id
    root = tmp_path
    m = json.loads((root / "MANIFEST.json").read_text())
    f = m["snapshots"]["2026-01-01"]["files"]["epss_2026-01-01.json"]
    raw = json.dumps({"records": {LOG4SHELL: [0.5, 0.5]}}).encode()
    (root / "epss_2026-01-01.json").write_bytes(raw)
    f["sha256"] = hashlib.sha256(raw).hexdigest()
    (root / "MANIFEST.json").write_text(json.dumps(m))
    assert load_snapshot(str(root)).id != first


# --- probability models -------------------------------------------------------

def _exploit(cve=None, **extra):
    a = {"id": "x", "preconditions": [{"type": "reachable", "from": "A", "to": "B"}],
         "effects": [{"type": "set_access", "host": "B", "level": "user"}], **extra}
    if cve:
        a["cve"] = cve
    return a


def test_three_models_on_log4shell(snap):
    a = _exploit(LOG4SHELL)
    p, basis = action_probability(a, ProbModel("cvss"), snap)
    assert basis == "cve-cvss" and p == pytest.approx(snap.cves[LOG4SHELL].exploitability / 10)
    assert action_probability(a, ProbModel("epss"), snap) == (0.99999, "cve-epss")
    assert action_probability(a, ProbModel("kev", p_kev=0.8), snap) == (0.8, "cve-kev")


def test_kev_model_falls_back_to_epss_outside_kev(snap):
    assert action_probability(_exploit(NOT_KEV), ProbModel("kev"), snap) == (0.0123, "cve-epss")


def test_cvss_model_matches_recost_vector_cost(snap):
    """M-CVSS gives the same p as `aapef recost`, before its rounding."""
    action = _exploit()
    action["preconditions"].append({"type": "env_fact", "fact": "vuln_B"})
    p, basis = action_probability(action, ProbModel("cvss"))
    model = CostModel()
    rounded = recost_scenario({"actions": [action]}, model)["actions"][0]["cost"]
    assert basis == "derived-cvss"
    assert round(model.scale * -math.log(p)) == rounded


def test_discovery_structural_and_native():
    scan = {"id": "s", "preconditions": [], "effects": [{"type": "learn", "fact": "k"}]}
    virtual = {"id": "g", "preconditions": [{"type": "access_at_least", "host": "B",
                                             "level": "admin"}],
               "effects": [{"type": "set_access", "host": "GOAL", "level": "admin"}]}
    vuln = _exploit(prob=0.8)
    vuln["preconditions"].append({"type": "env_fact", "fact": "vuln_B"})
    for name in ("cvss", "native"):
        assert action_probability(scan, ProbModel(name)) == (0.9, "discovery")
        assert action_probability(virtual, ProbModel(name)) == (1.0, "structural")
    assert action_probability(vuln, ProbModel("native")) == (0.8, "native")
    with pytest.raises(ValueError, match="needs a cve"):
        action_probability(vuln, ProbModel("epss"))
    del vuln["prob"]
    with pytest.raises(ValueError, match="'prob'"):
        action_probability(vuln, ProbModel("native"))


def test_unknown_cve_and_bad_model_are_errors(snap):
    with pytest.raises(ValueError, match="not in snapshot"):
        action_probability(_exploit("CVE-1999-9999"), ProbModel("epss"), snap)
    with pytest.raises(ValueError, match="unknown probability model"):
        cost_table({"actions": []}, ProbModel("nope"))


def test_float_costs_give_most_likely_path_on_small():
    """Dijkstra on -ln p costs: P* = exp(-C*) equals the product of step probabilities."""
    path = os.path.join(SCEN_DIR, "small.json")
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    sc = load_scenario(path)
    costs = cost_table(data, ProbModel("cvss"))
    assert costs["capture_all"] == 0.0
    assert all(isinstance(c, float) for c in costs.values())
    found, _ = dijkstra(initial_state(sc), weighted_successors(sc, costs),
                        lambda s: is_goal(s, sc.goal))
    assert found and found[-1] == "capture_all"
    probs = {a["id"]: action_probability(a, ProbModel("cvss"))[0] for a in data["actions"]}
    c_star = sum(costs[a] for a in found)
    assert math.exp(-c_star) == pytest.approx(math.prod(probs[a] for a in found))


def test_zero_probability_action_is_not_an_edge():
    path = os.path.join(SCEN_DIR, "small.json")
    sc = load_scenario(path)
    costs = {a.id: math.inf for a in sc.actions}
    found, m = dijkstra(initial_state(sc), weighted_successors(sc, costs),
                        lambda s: is_goal(s, sc.goal))
    assert found is None and m["edges_examined"] == 0


# --- role rule ----------------------------------------------------------------

def test_role_rule_on_hand_labelled_catalog():
    """Agreement of the rule with the hand-made catalog, recorded as-is.

    Disagreements (expected, the rule is an approximation): BlueKeep
    CVE-2019-0708 (AV:N/PR:N, labelled lateral) and Zerologon CVE-2020-1472
    (labelled domain-takeover, a role the rule cannot produce).
    """
    catalog = load_catalog(os.path.join(SCEN_DIR, "cve_catalog.json"))
    wrong = sorted(c for c, e in catalog.items()
                   if role_from_vector(e["parsed"]) != e["attack_role"])
    assert wrong == ["CVE-2019-0708", "CVE-2020-1472"]


def test_role_rule_examples():
    v = parse_vector_string
    assert role_from_vector(v("CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H")) == "client-side"
    assert role_from_vector(v("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H")) == "privesc"
    assert role_from_vector(v("CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")) == "initial-access"
    assert role_from_vector(v("CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H")) == "lateral"


# --- real snapshot (skipped until fetched) ------------------------------------

real = pytest.mark.skipif(not os.path.exists(os.path.join(SNAP_DIR, "MANIFEST.json")),
                          reason="no snapshot in data/snapshots")


@real
def test_real_snapshot_known_cves():
    s = load_snapshot(SNAP_DIR)
    log4 = s.cves[LOG4SHELL]
    assert log4.kev and log4.kev_added == "2021-12-10"
    assert log4.base_score == 10.0 and log4.vector["S"] == "C"
    assert log4.epss > 0.9
    assert s.cves[PWNKIT].kev and s.cves[PWNKIT].vector["AV"] == "L"
    assert sum(r.kev for r in s.cves.values()) == s.files[f"kev_{s.name}.json"]["records"]


def test_access_filter():
    from aapef.roles import grants_access, role_with_filter
    full = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    dos = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
    leak = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
    assert grants_access(full) and not grants_access(dos) and not grants_access(leak)
    assert role_with_filter(parse_vector_string(full), full) == "initial-access"
    assert role_with_filter(parse_vector_string(dos), dos) == "other"
