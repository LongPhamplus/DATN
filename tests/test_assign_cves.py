"""Tests for the group-V CVE assignment (reports/QuyTac_GanCVE.md)."""

import importlib.util
import json
import os

import pytest

from aapef.data import load_snapshot
from aapef.defense import patch_units, scenario_for_risk
from aapef.roles import role_with_filter

ROOT = os.path.join(os.path.dirname(__file__), os.pardir)
SNAP_DIR = os.path.join(ROOT, "data", "snapshots")

pytestmark = pytest.mark.skipif(not os.path.exists(os.path.join(SNAP_DIR, "MANIFEST.json")),
                                reason="no snapshot in data/snapshots")


@pytest.fixture(scope="module")
def ac():
    spec = importlib.util.spec_from_file_location(
        "assign_cves", os.path.join(ROOT, "scripts", "assign_cves.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def snap():
    return load_snapshot(SNAP_DIR)


@pytest.fixture(scope="module")
def small():
    with open(os.path.join(ROOT, "scenarios", "small.json"), encoding="utf-8") as fh:
        return json.load(fh)


def test_assignment_follows_the_rule(ac, snap, small):
    pool = ac.pools(snap)
    v = ac.assign(small, snap, 3, 0, pool=pool)
    scenario_for_risk(v)   # validates
    units = patch_units(v)
    assert len(units) == 14 * 3   # 14 slots x m
    assert all(u.startswith("CVE-") for u in units)
    for a in v["actions"]:
        if "cve" not in a:
            assert not any(p["type"] == "env_fact" for p in a["preconditions"])
            continue
        assert "prob" not in a and "cost" not in a
        rec = snap.cves[a["cve"]]
        role = role_with_filter(rec.vector, rec.vector_string)
        remote = any(p["type"] == "reachable" for p in a["preconditions"])
        assert role == ("initial-access" if remote else "privesc")
    for fact, cves in v["cve_assignment"]["slots"].items():
        assert len(set(cves)) == 3


def test_assignment_is_deterministic_and_seeded(ac, snap, small):
    pool = ac.pools(snap)
    a = ac.assign(small, snap, 2, 4, pool=pool)
    assert a == ac.assign(small, snap, 2, 4, pool=pool)
    assert a["cve_assignment"]["slots"] != ac.assign(small, snap, 2, 5, pool=pool)["cve_assignment"]["slots"]


def test_shared_variant_gives_same_cves_per_exploit(ac, snap, small):
    v = ac.assign(small, snap, 2, 0, shared=True)
    slots = v["cve_assignment"]["slots"]
    assert slots["vuln_H3_0_e_ftp"] == slots["vuln_H3_1_e_ftp"]
    assert slots["vuln_H3_0_e_ftp"] != slots["vuln_H2_0_e_ssh"]


def test_kev_share_variant_has_more_kev(ac, snap, small):
    pool = ac.pools(snap)
    def share(v):
        cves = [c for cs in v["cve_assignment"]["slots"].values() for c in cs]
        return sum(snap.cves[c].kev for c in cves) / len(cves)
    natural = sum(share(ac.assign(small, snap, 5, s, pool=pool)) for s in range(5)) / 5
    half = sum(share(ac.assign(small, snap, 5, s, kev_share=0.5, pool=pool)) for s in range(5)) / 5
    assert natural < 0.25 < half
