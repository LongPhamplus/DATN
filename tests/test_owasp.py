"""Tests for the OWASP risk model on the attack graph (aapef/owasp.py)."""

import glob
import heapq
import json
import math
import os

import pytest

from aapef import owasp as O
from aapef import policies as P
from aapef.cvss import exploitability, parse_vector_string
from aapef.data import CveRecord, Snapshot, load_snapshot
from aapef.defense import scenario_for_risk
from aapef.state import LEVELS, initial_state, state_key, successors

ROOT = os.path.join(os.path.dirname(__file__), os.pardir)
SNAP_DIR = os.path.join(ROOT, "data", "snapshots")


def _rec(cid, vs, epss=0.01, kev=False, base=7.5):
    vec = parse_vector_string(vs)
    return CveRecord(id=cid, vector_string=vs, vector=vec, base_score=base,
                     exploitability=exploitability(vec), epss=epss, kev=kev)


SNAP = Snapshot(id="test:0", name="test", files={}, cves={r.id: r for r in [
    _rec("CVE-2000-0001", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", kev=True, base=9.8),
    _rec("CVE-2000-0002", "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N", epss=0.5, base=3.7),
    _rec("CVE-2000-0003", "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H", base=7.5),
    _rec("CVE-2000-0004", "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", base=7.8),
    _rec("CVE-2000-0005", "CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", base=6.8),
]})


def _exploit(aid, src, dst, cve, service="http", level="user"):
    return {"id": aid, "name": f"e ({service}) from {src} on {dst}", "cve": cve,
            "preconditions": [{"type": "access_at_least", "host": src, "level": "user"},
                              {"type": "reachable", "from": src, "to": dst}],
            "effects": [{"type": "set_access", "host": dst, "level": level}]}


def _privesc(aid, host, cve):
    return {"id": aid, "name": f"pe on {host}", "cve": cve,
            "preconditions": [{"type": "access_at_least", "host": host, "level": "user"}],
            "effects": [{"type": "set_access", "host": host, "level": "admin"}]}


def _net(actions, hosts=("ATK", "H1_0", "H2_0", "H2_1")):
    topo = [[a, b] for a in hosts for b in hosts if a != b]
    return {"scenario_id": "t", "hosts": [{"id": h} for h in hosts], "topology": topo,
            "env_facts": [], "initial_state": {"access": {h: ("user" if h == "ATK" else "none")
                                                          for h in hosts}, "known": []},
            "actions": actions, "goal": {"type": "access_at_least", "host": "H2_0",
                                         "level": "admin"}}


# Two routes to H2_0: through H1_0 (easy KEV step, then a hard one) or
# direct (one medium step). Then a local privesc on H2_0.
NET = _net([
    _exploit("a1", "ATK", "H1_0", "CVE-2000-0001", level="admin"),
    _exploit("a2", "H1_0", "H2_0", "CVE-2000-0005", service="ssh"),
    _exploit("b1", "ATK", "H2_0", "CVE-2000-0003"),
    _privesc("c1", "H2_0", "CVE-2000-0004"),
])


def test_mapping_of_factors():
    cfg = O.make_config()
    f = O.step_factors(NET["actions"][0], cfg, SNAP)     # KEV, AV:N
    assert f["ease_of_exploit"] == 9 and f["ease_of_discovery"] == 9
    assert f["awareness"] == 9 and f["intrusion_detection"] == 8
    assert O.step_factors(NET["actions"][1], cfg, SNAP)["ease_of_discovery"] == 3   # AV:P
    assert O.step_factors(NET["actions"][2], cfg, SNAP)["ease_of_exploit"] == 3     # AC:H, UI:R
    assert O.step_factors(NET["actions"][3], cfg, SNAP)["ease_of_exploit"] == 5     # AC:L, UI:N
    two = _exploit("x", "ATK", "H1_0", "CVE-2000-0002")
    assert O.step_factors(two, cfg, SNAP)["ease_of_exploit"] == 7                   # EPSS 0.5
    scan = {"id": "s", "preconditions": [], "effects": [{"type": "learn", "fact": "k"}]}
    assert O.step_factors(scan, cfg, SNAP) is None


def test_levels_and_matrix():
    assert [O.level3(x) for x in (0, 2.99, 3, 5.99, 6, 9)] == \
        ["LOW", "LOW", "MEDIUM", "MEDIUM", "HIGH", "HIGH"]
    assert O.overall(7, 7) == "Critical" and O.overall(4, 7) == "High"
    assert O.overall(2, 2) == "Note" and O.overall(0, 9) == "Note"
    assert O.overall(7, 2) == "Medium"


def test_config_validation():
    with pytest.raises(ValueError):
        O.make_config({"threat_profile": {"skill": 12}})
    with pytest.raises(ValueError):
        O.make_config({"acceptable_risk": "Huge"})
    cfg = O.make_config({"threat_profile": {"skill": 9}})
    assert cfg["threat_profile"]["motive"] == 4        # other defaults kept


def test_asset_likelihood_is_the_widest_path():
    cfg = O.make_config()
    o = O.OwaspOracle(NET, cfg, SNAP)
    L = {a["id"]: O.step_likelihood(a, cfg, SNAP) for a in NET["actions"]}
    via_h1 = min(L["a1"], L["a2"], L["c1"])
    direct = min(L["b1"], L["c1"])
    r = o.assess([])["H2_0"]
    assert r["likelihood"] == pytest.approx(max(via_h1, direct))
    assert set(r["path"]) == ({"b1", "c1"} if direct >= via_h1 else {"a1", "a2", "c1"})
    # patching the privesc closes every path
    assert o(["CVE-2000-0004@H2_0"]) == 0
    assert o.assess(["CVE-2000-0004@H2_0"])["H2_0"]["level"] == "Note"


def test_intrusion_detection_per_zone_lowers_likelihood():
    base = O.OwaspOracle(NET, O.make_config(), SNAP).assess([])["H2_0"]["likelihood"]
    cfg = O.make_config({"intrusion_detection": {"zones": {"S2": 1}}})
    watched = O.OwaspOracle(NET, cfg, SNAP).assess([])["H2_0"]["likelihood"]
    assert watched == pytest.approx(base - 7 / 8)


def test_business_impact_overrides_technical():
    cfg = O.make_config({"assets": {"H2_0": {"owner": "finance", "business": {
        "financial": 2, "reputation": 2, "non_compliance": 2, "privacy": 2}}}})
    r = O.OwaspOracle(NET, cfg, SNAP).assess([])["H2_0"]
    assert r["impact"] == 2 and r["impact_basis"] == "business"
    assert r["level"] == "Medium"


def test_block_units_respect_business_flows():
    cfg = O.make_config()
    units = O.block_units(NET, cfg)
    assert list(units) == ["block:S1>S2:ssh"]          # Internet flows are business flows
    assert units["block:S1>S2:ssh"] == ["a2"]
    cfg2 = O.make_config({"business_flows": []})
    assert "block:Internet>S2:http" in O.block_units(NET, cfg2)
    o = O.OwaspOracle(NET, cfg2, SNAP, kinds=("block",))
    assert o(["block:Internet>S2:http", "block:S1>S2:ssh"]) == 0


def test_greedy_matches_optimum_on_small_net():
    cfg = O.make_config({"business_flows": []})
    o = O.OwaspOracle(NET, cfg, SNAP, kinds=("patch", "block"))
    opt = P.optimal(o, 2)
    g = O.greedy(o, 2)
    assert o(g[:1]) == opt[1][0]
    assert O.until_accepted(o, 5)[1]


def test_per_vulnerability_policy_orders_by_owasp_score():
    cfg = O.make_config()
    from aapef.defense import patch_units
    order = O.per_vulnerability(NET, patch_units(NET), cfg, SNAP)
    assert order[0] == "CVE-2000-0001@H1_0"            # KEV, critical C/I/A


def _brute(data, oracle, host):
    """Widest path over the explicit state space (reference)."""
    sc = scenario_for_risk(data)
    start = initial_state(sc)
    best, heap, t, done = {state_key(start): math.inf}, [(-math.inf, 0, start)], 1, set()
    while heap:
        nv, _, s = heapq.heappop(heap)
        k = state_key(s)
        if k in done:
            continue
        done.add(k)
        if LEVELS[s.access[host]] >= 2:
            return 9.0 if nv == -math.inf else -nv
        for a, n, _c in successors(s, sc):
            L = oracle.step_L[a.id]
            w = min(-nv, math.inf if L is None else L)
            kn = state_key(n)
            if w > best.get(kn, -1):
                best[kn] = w
                heapq.heappush(heap, (-w, t, n))
                t += 1
    return 0.0


@pytest.mark.skipif(not glob.glob(os.path.join(ROOT, "scenarios", "V", "small-m*-s0.json")),
                    reason="group V scenarios not generated")
def test_relaxed_widest_path_equals_state_space_search():
    snap = load_snapshot(SNAP_DIR)
    cfg = O.make_config({"intrusion_detection": {"zones": {"S3": 3}}})
    files = sorted(glob.glob(os.path.join(ROOT, "scenarios", "V", "small*-m[13]-s[01].json")))
    assert files
    for f in files:
        with open(f, encoding="utf-8") as fh:
            data = json.load(fh)
        o = O.OwaspOracle(data, cfg, snap)
        for h, r in o.assess([]).items():
            assert r["likelihood"] == pytest.approx(_brute(data, o, h)), (f, h)
        u = O.greedy(o, 1)
        if u:
            for h, r in o.assess(u).items():
                patched = {a: d for a, d in data.items()}
                drop = set(o.unit_actions[u[0]])
                patched["actions"] = [a for a in data["actions"] if a["id"] not in drop]
                o2 = O.OwaspOracle(patched, cfg, snap)
                assert r["likelihood"] == pytest.approx(_brute(patched, o2, h)), (f, h, u)


# ----------------------------------------------------------- assess (SP 800-30) --

def _assess_net():
    data = json.loads(json.dumps(NET))
    data["hosts"] = [{"id": "ATK", "ip": "10.0.0.1"},
                     {"id": "H1_0", "ip": "10.0.1.1", "services": [{"name": "ssh", "port": 22}]},
                     {"id": "H2_0", "ip": "10.0.2.1",
                      "services": [{"name": "ssh", "protocol": "tcp", "port": 22}]},
                     {"id": "H2_1", "ip": "10.0.2.2"}]
    return data


def test_assess_writes_register_plan_rules_and_layer(tmp_path):
    from aapef.assess import assess, write_outputs
    data = _assess_net()
    cfg = O.make_config({"assets": {"H2_0": {"owner": "finance", "business": {
        "financial": 9, "reputation": 7, "non_compliance": 7, "privacy": 9}}}})
    res = assess(data, cfg, SNAP, ("patch", "block"), max_measures=5)
    assert res["risks"][0]["risk"] == "Critical" and res["accepted"]
    assert res["risks"][0]["residual_risk"] == "Note"
    write_outputs(res, data, str(tmp_path))
    for name in ("assessment.json", "risk_register.csv", "treatment_plan.csv",
                 "firewall_rules.nft", "attack_navigator_layer.json", "report.md"):
        assert (tmp_path / name).exists(), name
    layer = json.loads((tmp_path / "attack_navigator_layer.json").read_text())
    assert layer["domain"] == "enterprise-attack"
    assert {t["techniqueID"] for t in layer["techniques"]} <= {"T1046", "T1190", "T1210", "T1068"}
    reg = (tmp_path / "risk_register.csv").read_text(encoding="utf-8")
    assert "R-01" in reg and "finance" in reg


def test_nft_rules_match_the_block_measures():
    from aapef.assess import nft_rules
    data = _assess_net()
    res = {"config": O.make_config(), "scenario_id": "t", "date": "2026-11-03",
           "treatment_plan": [{"step": 1, "measure": "block:S1>S2:ssh", "type": "block",
                               "removes_actions": 1}]}
    text = nft_rules(res, data)
    assert "ip saddr 10.0.1.0/24 ip daddr 10.0.2.0/24 tcp dport 22 drop" in text


def _nft_check_available():
    import shutil
    import subprocess
    if not (shutil.which("unshare") and os.path.exists("/usr/sbin/nft")):
        return False
    r = subprocess.run(["unshare", "-rn", "/usr/sbin/nft", "-c", "add", "table", "inet", "t"],
                       capture_output=True)
    return r.returncode == 0


@pytest.mark.skipif(not _nft_check_available(), reason="nft / user namespaces not available")
def test_nft_rules_pass_nft_syntax_check(tmp_path):
    import subprocess
    from aapef.assess import nft_rules
    data = _assess_net()
    res = {"config": O.make_config(), "scenario_id": "t", "date": "2026-11-03",
           "treatment_plan": [{"step": 1, "measure": "block:S1>S2:ssh", "type": "block",
                               "removes_actions": 1},
                              {"step": 2, "measure": "block:S1>S2:smb", "type": "block",
                               "removes_actions": 1}]}
    f = tmp_path / "r.nft"
    f.write_text(nft_rules(res, data))
    r = subprocess.run(["unshare", "-rn", "/usr/sbin/nft", "-c", "-f", str(f)],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr


def test_compare_reports_changed_risks():
    from aapef.assess import compare
    prev = {"risks": [{"asset": "H2_0", "risk": "Critical", "likelihood": 7.0}]}
    cur = {"risks": [{"asset": "H2_0", "risk": "High", "likelihood": 5.5}]}
    assert compare(prev, cur)[0]["after"] == "High"
    assert compare(prev, prev) == []
