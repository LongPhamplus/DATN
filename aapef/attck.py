"""MITRE ATT&CK labels and plain-language narration of attack paths (MasterPlan §5.4).

Presentation only: the labels never change a number. A step is labelled by
where it sits in the attack graph, which is what an ATT&CK technique
describes (a technique as used), not by the CVE's own role:

    scan (no set_access)                         T1046 Network Service Discovery
    exploit over the network from a start host   T1190 Exploit Public-Facing Application
    exploit over the network from a taken host   T1210 Exploitation of Remote Services
    exploit without network step (local)         T1068 Exploitation for Privilege Escalation
    structural step (no vulnerability)           no technique

A start host is one the attacker already holds in the initial state (e.g. the
`ATK` host of converted NASim scenarios). If the action names a CVE, the
CVE's vector-derived role (aapef.roles) is shown next to the label.

    python -m aapef.attck scenarios/small.json --model cvss [--patch U1,U2]
"""

import argparse
import json

from .defense import RiskOracle, patch_units, scenario_for_risk, sensitive_hosts
from .prob import ProbModel, action_probability, cost_table, is_vulnerability
from .roles import role_with_filter

TECHNIQUES = {
    "T1046": ("Network Service Discovery", "Discovery"),
    "T1190": ("Exploit Public-Facing Application", "Initial Access"),
    "T1210": ("Exploitation of Remote Services", "Lateral Movement"),
    "T1068": ("Exploitation for Privilege Escalation", "Privilege Escalation"),
}


def technique(action, start_hosts):
    """ATT&CK technique id for one raw action dict, or None (structural step)."""
    if not any(e["type"] == "set_access" for e in action["effects"]):
        return "T1046"
    if not (action.get("cve") or is_vulnerability(action)):
        return None
    sources = [p["from"] for p in action.get("preconditions", []) if p["type"] == "reachable"]
    if not sources:
        return "T1068"
    return "T1190" if all(s in start_hosts for s in sources) else "T1210"


def narrate(data, path, model, snapshot=None):
    """Lines describing `path` (action ids) step by step, with probabilities."""
    by_id = {a["id"]: a for a in data["actions"]}
    start = {h for h, lvl in data["initial_state"]["access"].items() if lvl != "none"}
    lines, total = [], 1.0
    for i, aid in enumerate(path, 1):
        a = by_id[aid]
        p, basis = action_probability(a, model, snapshot)
        total *= p
        tid = technique(a, start)
        label = f"{tid} {TECHNIQUES[tid][0]} [{TECHNIQUES[tid][1]}]" if tid else "(no technique)"
        extra = ""
        if a.get("cve"):
            extra = f"  {a['cve']}"
            rec = snapshot.cves.get(a["cve"]) if snapshot else None
            if rec and rec.vector:
                extra += f" (vector role: {role_with_filter(rec.vector, rec.vector_string)})"
        lines.append(f"{i:2d}. {label:62s} {aid}  p={p:.3f} ({basis}){extra}")
    lines.append(f"    path success probability P = {total:.4g}")
    return lines


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("scenario")
    ap.add_argument("--model", default="cvss")
    ap.add_argument("--p-kev", type=float, default=ProbModel("kev").p_kev)
    ap.add_argument("--snapshot", default=None)
    ap.add_argument("--patch", default="", help="comma list of patch units applied first")
    args = ap.parse_args(argv)
    with open(args.scenario, encoding="utf-8") as fh:
        data = json.load(fh)
    snap = None
    if args.snapshot:
        from .data import load_snapshot
        snap = load_snapshot(args.snapshot)
    model = ProbModel(args.model, p_kev=args.p_kev)
    model.validate()
    targets = sensitive_hosts(data)
    oracle = RiskOracle(scenario_for_risk(data), cost_table(data, model, snap),
                        patch_units(data), targets)
    patched = [u for u in args.patch.split(",") if u]
    p, path = oracle.evaluate(patched)
    print(f"{data['scenario_id']}: model {model.name}, targets {' '.join(targets)}, "
          f"patched {patched or 'nothing'}")
    if path is None:
        print("    no attack path left: every target is unreachable")
        return
    for line in narrate(data, path, model, snap):
        print(line)


if __name__ == "__main__":
    main()
