"""Tests for the ATT&CK labels and path narration (presentation only)."""

import json
import os

from aapef.attck import main, narrate, technique
from aapef.prob import ProbModel

SCEN_DIR = os.path.join(os.path.dirname(__file__), os.pardir, "scenarios")


def _small():
    with open(os.path.join(SCEN_DIR, "small.json"), encoding="utf-8") as fh:
        return json.load(fh)


def test_techniques_by_position_in_graph():
    data = _small()
    by_id = {a["id"]: a for a in data["actions"]}
    start = {"ATK"}
    assert technique(by_id["e_http_ATK_to_H1_0"], start) == "T1190"
    assert technique(by_id["e_ssh_H1_0_to_H2_0"], start) == "T1210"
    assert technique(by_id["pe_tomcat_H2_0"], start) == "T1068"
    assert technique(by_id["discover_H1_0_S2"], start) == "T1046"
    assert technique(by_id["capture_all"], start) is None


def test_narration_probability_matches_path():
    data = _small()
    path = ["e_http_ATK_to_H1_0", "discover_H1_0_S2", "e_ssh_H1_0_to_H2_0", "pe_tomcat_H2_0"]
    lines = narrate(data, path, ProbModel("cvss"))
    assert len(lines) == len(path) + 1
    assert "T1190" in lines[0] and "T1068" in lines[3]
    assert lines[-1].strip() == "path success probability P = 0.01327"


def test_cli_reports_blocked_network(capsys):
    main([os.path.join(SCEN_DIR, "small.json"), "--patch", "vuln_H1_0_e_http"])
    assert "no attack path left" in capsys.readouterr().out
