"""Risk assessment of one network following NIST SP 800-30 Rev. 1 (AAPEF v2).

OWASP Risk Rating is the analysis method (aapef/owasp.py); this module runs
the SP 800-30 process around it and writes what the process asks for:

  Step 1  Prepare        purpose, scope, assumptions, information sources
  Task 2-1 threat sources       threat profile of the organisation
  Task 2-2 threat events        attack path per asset, as MITRE ATT&CK steps
  Task 2-3 vulnerabilities and predisposing conditions
                                CVE@host on the path, zone flows it crosses
  Task 2-4 likelihood, 2-5 impact, 2-6 risk     OWASP factors and matrix
  Risk response (SP 800-39)     ordered measures (patch, firewall block)
                                until every asset meets the acceptance level
  Step 3  Communicate    risk register, treatment plan, report
  Step 4  Maintain       re-run with a newer snapshot; --previous compares

    python -m aapef.assess scenarios/V/small-m1-s0.json --config configs/org_example.json \
        --snapshot data/snapshots --out out/assess/small --measures patch,block

Output files in --out:
    assessment.json           everything below, machine-readable
    risk_register.csv         one row per asset (SP 800-30 Table I-5 fields)
    treatment_plan.csv        measures in order with the residual risk after each
    firewall_rules.nft        nftables rules for the block measures (not applied)
    attack_navigator_layer.json   layer for MITRE ATT&CK Navigator
    report.md                 the assessment report (Vietnamese)

Simulation only: nothing is scanned, exploited or changed on any host.
"""

import argparse
import csv
import datetime
import ipaddress
import json
import os

from . import owasp as O
from .attck import TECHNIQUES, technique

TACTIC_SHORT = {"Discovery": "discovery", "Initial Access": "initial-access",
                "Lateral Movement": "lateral-movement",
                "Privilege Escalation": "privilege-escalation"}


def _steps(data, path, oracle, cfg):
    by_id = {a["id"]: a for a in data["actions"]}
    start = {h for h, lvl in data["initial_state"]["access"].items() if lvl != "none"}
    out = []
    for aid in path or []:
        a = by_id[aid]
        tid = technique(a, start)
        target = next((e["host"] for e in a["effects"] if e["type"] == "set_access"), None)
        src = next((p["from"] for p in a["preconditions"] if p["type"] == "reachable"), None)
        out.append({"action": aid, "technique": tid,
                    "technique_name": TECHNIQUES[tid][0] if tid else None,
                    "tactic": TECHNIQUES[tid][1] if tid else None,
                    "cve": a.get("cve"), "target": target, "source": src,
                    "flow": (f"{O.zone_of(src, cfg)}>{O.zone_of(target, cfg)}:"
                             f"{O.action_service(a)}") if src and target else None,
                    "likelihood": oracle.step_L.get(aid)})
    return out


def assess(data, cfg, snapshot, kinds=("patch",), max_measures=20, lookahead=True):
    """The whole assessment as a dict (see the module docstring)."""
    oracle = O.OwaspOracle(data, cfg, snapshot, kinds)
    before = oracle.assess([])
    plan, accepted = O.until_accepted(oracle, max_measures, lookahead)
    after = oracle.assess(plan)
    by_id = {a["id"]: a for a in data["actions"]}
    steps = []
    for k, u in enumerate(plan, 1):
        res = oracle.assess(plan[:k])
        acts = oracle.unit_actions[u]
        steps.append({"step": k, "measure": u, "type": "block" if u.startswith("block:") else "patch",
                      "removes_actions": len(acts),
                      "cve": sorted({by_id[a].get("cve") for a in acts if by_id[a].get("cve")}),
                      "risk_after": oracle(plan[:k]),
                      "assets_above_acceptance": [h for h, r in res.items()
                                                  if not O.at_most(r["level"], cfg["acceptable_risk"])],
                      "levels_after": {h: r["level"] for h, r in res.items()}})
    risks = []
    for n, h in enumerate(oracle.assets, 1):
        b, a = before[h], after[h]
        st = _steps(data, b["path"], oracle, cfg)
        asset_cfg = cfg["assets"].get(h, {})
        touching = [s["measure"] for s in steps
                    if set(oracle.unit_actions[s["measure"]]) & set(b["path"] or [])]
        risks.append({
            "risk_id": f"R-{n:02d}", "asset": h, "owner": asset_cfg.get("owner", ""),
            "zone": O.zone_of(h, cfg), "threat_source": cfg["threat_profile"].get("name", ""),
            "threat_event": " -> ".join(
                f"{s['technique'] or '-'}@{s['target']}" if s["target"] else (s["technique"] or "-")
                for s in st),
            "steps": st,
            "vulnerabilities": [f"{s['cve']}@{s['target']}" for s in st if s["cve"]],
            "flows": sorted({s["flow"] for s in st if s["flow"]}),
            "likelihood": b["likelihood"], "likelihood_level": O.level3(b["likelihood"]),
            "impact": b["impact"], "impact_level": O.level3(b["impact"]),
            "impact_basis": b["impact_basis"], "risk": b["level"],
            "response": "accept" if O.at_most(b["level"], cfg["acceptable_risk"]) else "mitigate",
            "measures": touching,
            "residual_likelihood": a["likelihood"], "residual_risk": a["level"]})
    return {
        "standard": "NIST SP 800-30 Rev. 1 process; OWASP Risk Rating Methodology analysis",
        "date": datetime.date.today().isoformat(),
        "scenario_id": data["scenario_id"], "snapshot_id": snapshot.id if snapshot else None,
        "scope": {"hosts": len([x for x in data["hosts"] if x["id"] not in ("ATK", "GOAL")]),
                  "zones": sorted({O.zone_of(x["id"], cfg) for x in data["hosts"]
                                   if x["id"] != "GOAL"}),
                  "assets": oracle.assets, "vulnerability_instances": len(O.patch_units(data))},
        "config": cfg, "measure_kinds": list(kinds), "max_measures": max_measures,
        "risk_before": oracle([]), "risk_after": oracle(plan), "accepted": accepted,
        "risks": risks, "treatment_plan": steps, "evaluations": oracle.searches,
    }


# ------------------------------------------------------------------ outputs --

def _zone_net(data, zone, cfg):
    ips = [h.get("ip") for h in data["hosts"] if O.zone_of(h["id"], cfg) == zone and h.get("ip")]
    if not ips:
        return None
    nets = {ipaddress.ip_network(f"{ip}/24", strict=False) for ip in ips}
    return str(nets.pop()) if len(nets) == 1 else "{ " + ", ".join(sorted(ips)) + " }"


def _port(data, zone, service, cfg):
    for h in data["hosts"]:
        if O.zone_of(h["id"], cfg) != zone:
            continue
        for s in h.get("services", []):
            if s.get("name") == service and s.get("port"):
                return s.get("protocol", "tcp"), s["port"]
    return None


def nft_rules(result, data):
    cfg = result["config"]
    lines = [f"# AAPEF v2 recommended firewall rules for {result['scenario_id']}",
             f"# generated {result['date']}; NOT applied. Check with: nft -c -f firewall_rules.nft",
             "table inet aapef_recommended {", "  chain forward {",
             "    type filter hook forward priority 0; policy accept;"]
    n = 0
    for s in result["treatment_plan"]:
        if s["type"] != "block":
            continue
        n += 1
        src, rest = s["measure"][len("block:"):].split(">", 1)
        dst, service = rest.split(":", 1)
        lines.append(f"    # {s['step']}. block {src} -> {dst} service {service} "
                     f"(removes {s['removes_actions']} attack steps)")
        match = []
        sn = None if src == "Internet" else _zone_net(data, src, cfg)
        dn = _zone_net(data, dst, cfg)
        if sn:
            match.append(f"ip saddr {sn}")
        if dn:
            match.append(f"ip daddr {dn}")
        port = _port(data, dst, service, cfg) if service != "*" else None
        if port:
            match.append(f"{port[0]} dport {port[1]}")
        elif service != "*":
            lines.append(f"    # port of service {service!r} unknown: rule blocks all traffic "
                         "between the zones; restrict it to the service port")
        lines.append("    " + " ".join(match) + " drop")
    if n == 0:
        lines.append("    # no block measure in the plan")
    lines += ["  }", "}"]
    return "\n".join(lines) + "\n"


def navigator_layer(result):
    count, comments = {}, {}
    for r in result["risks"]:
        for s in r["steps"]:
            if not s["technique"]:
                continue
            key = (s["technique"], TACTIC_SHORT[s["tactic"]])
            count[key] = count.get(key, 0) + 1
            comments.setdefault(key, []).append(f"{r['risk_id']} {r['asset']}: {s['action']}")
    top = max(count.values(), default=1)
    return {
        "name": f"AAPEF v2 - {result['scenario_id']}",
        "versions": {"attack": "16", "navigator": "5.1.0", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": "Techniques on the most likely attack path to each asset "
                       "(score = number of path steps).",
        "techniques": [{"techniqueID": t, "tactic": tac, "score": c,
                        "comment": "; ".join(comments[(t, tac)][:20])}
                       for (t, tac), c in sorted(count.items())],
        "gradient": {"colors": ["#ffe766", "#ff6666"], "minValue": 0, "maxValue": top},
    }


REGISTER_FIELDS = ["risk_id", "asset", "owner", "zone", "threat_source", "threat_event",
                   "vulnerabilities", "flows", "likelihood", "likelihood_level", "impact",
                   "impact_level", "impact_basis", "risk", "response", "measures",
                   "residual_likelihood", "residual_risk", "snapshot_id"]


def write_outputs(result, data, out):
    os.makedirs(out, exist_ok=True)
    with open(os.path.join(out, "assessment.json"), "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=1, ensure_ascii=False)
    with open(os.path.join(out, "risk_register.csv"), "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=REGISTER_FIELDS)
        w.writeheader()
        for r in result["risks"]:
            row = {k: r.get(k) for k in REGISTER_FIELDS}
            row["snapshot_id"] = result["snapshot_id"]
            for k in ("vulnerabilities", "flows", "measures"):
                row[k] = " ".join(r[k])
            for k in ("likelihood", "impact", "residual_likelihood"):
                row[k] = round(r[k], 3)
            w.writerow(row)
    with open(os.path.join(out, "treatment_plan.csv"), "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["step", "measure", "type", "cve", "removes_actions", "risk_after",
                    "assets_above_acceptance"])
        for s in result["treatment_plan"]:
            w.writerow([s["step"], s["measure"], s["type"], " ".join(s["cve"]),
                        s["removes_actions"], round(s["risk_after"], 3),
                        " ".join(s["assets_above_acceptance"])])
    with open(os.path.join(out, "firewall_rules.nft"), "w", encoding="utf-8") as fh:
        fh.write(nft_rules(result, data))
    with open(os.path.join(out, "attack_navigator_layer.json"), "w", encoding="utf-8") as fh:
        json.dump(navigator_layer(result), fh, indent=1)
    with open(os.path.join(out, "report.md"), "w", encoding="utf-8") as fh:
        fh.write(report_md(result))


def compare(previous, current):
    """Step 4 (maintain): risks whose level changed between two assessments."""
    old = {r["asset"]: r for r in previous["risks"]}
    out = []
    for r in current["risks"]:
        o = old.get(r["asset"])
        if o is None or o["risk"] != r["risk"] or abs(o["likelihood"] - r["likelihood"]) > 1e-9:
            out.append({"asset": r["asset"], "before": o and o["risk"], "after": r["risk"],
                        "likelihood_before": o and o["likelihood"],
                        "likelihood_after": r["likelihood"]})
    return out


def report_md(res):
    cfg, tp = res["config"], res["config"]["threat_profile"]
    L = []
    add = L.append
    add(f"# Báo cáo đánh giá rủi ro: {res['scenario_id']}\n")
    add(f"Ngày {res['date']}. Quy trình theo NIST SP 800-30 Rev. 1; phân tích bằng OWASP Risk "
        f"Rating Methodology trên attack graph. Dữ liệu lỗ hổng: snapshot `{res['snapshot_id']}`. "
        "Kết quả là mô phỏng, không có thao tác nào trên hệ thống thật.\n")
    add("## 1. Chuẩn bị (Step 1)\n")
    sc = res["scope"]
    add(f"- **Mục đích**: xác định rủi ro của các tài sản quan trọng và thứ tự biện pháp "
        f"giảm rủi ro.\n- **Phạm vi**: {sc['hosts']} máy, các vùng {', '.join(sc['zones'])}; "
        f"{sc['vulnerability_instances']} lỗ hổng (CVE@host); tài sản: {', '.join(sc['assets'])}.\n"
        f"- **Tiêu chí chấp nhận rủi ro**: mức ≤ {cfg['acceptable_risk']}.\n"
        f"- **Giả định**: các bước tấn công độc lập; kẻ tấn công xuất phát từ Internet; luồng "
        f"nghiệp vụ không được chặn: {cfg['business_flows']}.\n"
        f"- **Biện pháp xét**: {', '.join(res['measure_kinds'])}; tối đa {res['max_measures']}.\n")
    add("## 2. Đánh giá (Step 2)\n")
    add(f"**Task 2-1, nguồn đe dọa**: hồ sơ `{tp.get('name')}`: Skill {tp['skill']}, Motive "
        f"{tp['motive']}, Opportunity {tp['opportunity']}, Size {tp['size']}.\n")
    add("**Task 2-2 đến 2-6**: mỗi tài sản, đường tấn công có khả năng cao nhất "
        "(Likelihood của đường = bước khó nhất).\n")
    add("| Mã | Tài sản | Vùng | Likelihood | Impact | Rủi ro | Xử lý |")
    add("|---|---|---|---|---|---|---|")
    for r in res["risks"]:
        add(f"| {r['risk_id']} | {r['asset']} | {r['zone']} | {r['likelihood']:.2f} "
            f"({r['likelihood_level']}) | {r['impact']:.2f} ({r['impact_level']}) | "
            f"**{r['risk']}** | {r['response']} |")
    add("")
    for r in res["risks"]:
        add(f"### {r['risk_id']}: {r['asset']}\n")
        if not r["steps"]:
            add("Không có đường tấn công.\n")
            continue
        add("| # | Kỹ thuật ATT&CK | Bước | CVE | Luồng | Likelihood bước |")
        add("|---|---|---|---|---|---|")
        for i, s in enumerate(r["steps"], 1):
            lk = "-" if s["likelihood"] is None else f"{s['likelihood']:.3f}"
            tech = f"{s['technique']} {s['technique_name']}" if s["technique"] else "-"
            add(f"| {i} | {tech} | `{s['action']}` | {s['cve'] or '-'} | {s['flow'] or '-'} | {lk} |")
        add("")
    add("## 3. Xử lý rủi ro (SP 800-39)\n")
    add(f"Rủi ro tổng (Σ Likelihood × Impact): {res['risk_before']:.2f} → {res['risk_after']:.2f}. "
        f"{'Đạt' if res['accepted'] else 'Chưa đạt'} tiêu chí chấp nhận sau "
        f"{len(res['treatment_plan'])} biện pháp.\n")
    if res["treatment_plan"]:
        add("| Bước | Biện pháp | Loại | Rủi ro tổng sau | Tài sản còn trên ngưỡng |")
        add("|---|---|---|---|---|")
        for s in res["treatment_plan"]:
            add(f"| {s['step']} | `{s['measure']}` | {s['type']} | {s['risk_after']:.2f} | "
                f"{', '.join(s['assets_above_acceptance']) or '-'} |")
        add("")
    add("## 4. Truyền đạt và duy trì (Step 3, 4)\n")
    add("Kèm theo: `risk_register.csv`, `treatment_plan.csv`, `firewall_rules.nft` (chưa áp dụng), "
        "`attack_navigator_layer.json` (mở bằng MITRE ATT&CK Navigator). Đánh giá lại khi có "
        "snapshot NVD/EPSS/KEV mới hoặc khi mạng thay đổi (`--previous`).\n")
    return "\n".join(L)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("scenario")
    ap.add_argument("--config", default=None, help="organisation settings (JSON)")
    ap.add_argument("--snapshot", default="data/snapshots")
    ap.add_argument("--snapshot-name", default=None)
    ap.add_argument("--measures", default="patch", help="patch, block or patch,block")
    ap.add_argument("--max-measures", type=int, default=20)
    ap.add_argument("--previous", default=None, help="assessment.json of an earlier run")
    ap.add_argument("--out", required=True)
    args = ap.parse_args(argv)
    from .data import load_snapshot
    with open(args.scenario, encoding="utf-8") as fh:
        data = json.load(fh)
    snap = load_snapshot(args.snapshot, args.snapshot_name)
    cfg = O.load_config(args.config)
    res = assess(data, cfg, snap, tuple(args.measures.split(",")), args.max_measures)
    if args.previous:
        with open(args.previous, encoding="utf-8") as fh:
            res["changes_since_previous"] = compare(json.load(fh), res)
    write_outputs(res, data, args.out)
    for r in res["risks"]:
        print(f"{r['risk_id']} {r['asset']:8} L={r['likelihood']:.2f} I={r['impact']:.2f} "
              f"{r['risk']:8} -> {r['residual_risk']}")
    print(f"plan: {len(res['treatment_plan'])} measure(s), accepted={res['accepted']}; "
          f"wrote {os.path.abspath(args.out)}")


if __name__ == "__main__":
    main()
