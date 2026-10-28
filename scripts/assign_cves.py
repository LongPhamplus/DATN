"""Assign real CVEs to the vulnerability slots of NASim scenarios (group V).

Implements the pre-registered rule in reports/QuyTac_GanCVE.md. Every
`vuln_<host>_<exploit>` env_fact is a slot; its exploit actions are replaced
by `m` copies, one per CVE drawn from the candidate pool of the slot's role:

    remote exploit (has a `reachable` precondition)  -> role initial-access
    local exploit (privilege escalation)             -> role privesc with AV:L

    python scripts/assign_cves.py scenarios/small.json ... --m 1,2,3,5 \
        --seeds 10 --out scenarios/V [--kev-share 0.5] [--shared]

Writes <out>/<structure>-m<m>-s<seed>.json and <out>/MANIFEST.json.
"""

import argparse
import copy
import hashlib
import json
import os
import random
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir))

from aapef.data import load_snapshot  # noqa: E402
from aapef.roles import role_with_filter  # noqa: E402

RULE = "reports/QuyTac_GanCVE.md"


def pools(snapshot):
    """{"remote": [...], "local": [...]} CVE ids, sorted, usable by every model."""
    out = {"remote": [], "local": []}
    for r in snapshot.cves.values():
        if not (r.vector and r.epss is not None and r.base_score is not None):
            continue
        role = role_with_filter(r.vector, r.vector_string)
        if role == "initial-access":
            out["remote"].append(r.id)
        elif role == "privesc" and r.vector["AV"] == "L":
            out["local"].append(r.id)
    return {k: sorted(v) for k, v in out.items()}


def _target(action):
    return next(e["host"] for e in action["effects"] if e["type"] == "set_access")


def slots(data):
    """{slot fact: (kind, exploit name, [action indexes])}, slots sorted by fact."""
    out = {}
    for i, a in enumerate(data["actions"]):
        facts = [p["fact"] for p in a["preconditions"] if p["type"] == "env_fact"]
        if not facts:
            continue
        if len(facts) != 1:
            raise ValueError(f"action {a['id']!r}: expected one vulnerability env_fact")
        fact = facts[0]
        kind = "remote" if any(p["type"] == "reachable" for p in a["preconditions"]) else "local"
        prefix = f"vuln_{_target(a)}_"
        if not fact.startswith(prefix):
            raise ValueError(f"action {a['id']!r}: env_fact {fact!r} does not name its target")
        entry = out.setdefault(fact, (kind, fact[len(prefix):], []))
        if entry[0] != kind:
            raise ValueError(f"slot {fact!r} is used by remote and local actions")
        entry[2].append(i)
    return {k: out[k] for k in sorted(out)}


def draw(rng, pool, kev, m, kev_share):
    """m distinct CVEs: uniform over the pool, or stratified KEV / non-KEV."""
    if kev_share is None:
        return rng.sample(pool, m)
    in_kev = [c for c in pool if c in kev]
    out_kev = [c for c in pool if c not in kev]
    picked = []
    while len(picked) < m:
        src = in_kev if rng.random() < kev_share else out_kev
        c = rng.choice(src)
        if c not in picked:
            picked.append(c)
    return picked


def assign(data, snapshot, m, seed, kev_share=None, shared=False, pool=None):
    """Group-V copy of scenario dict `data` (see reports/QuyTac_GanCVE.md §4)."""
    pool = pool or pools(snapshot)
    kev = {c for c in pool["remote"] + pool["local"] if snapshot.cves[c].kev}
    rng = random.Random(f"{data['scenario_id']}|m={m}|seed={seed}")
    chosen, by_exploit = {}, {}
    for fact, (kind, exploit, _) in slots(data).items():
        if shared:   # same CVE set for the same NASim exploit on every host
            if exploit not in by_exploit:
                by_exploit[exploit] = draw(rng, pool[kind], kev, m, kev_share)
            chosen[fact] = by_exploit[exploit]
        else:
            chosen[fact] = draw(rng, pool[kind], kev, m, kev_share)
    out = copy.deepcopy(data)
    actions = []
    for a in data["actions"]:
        facts = [p["fact"] for p in a["preconditions"] if p["type"] == "env_fact"]
        if not facts:
            actions.append(copy.deepcopy(a))
            continue
        for cve in chosen[facts[0]]:
            b = {k: copy.deepcopy(v) for k, v in a.items() if k not in ("prob", "cost")}
            b["id"] = f"{a['id']}__{cve}"
            b["name"] = f"{a.get('name', a['id'])} via {cve}"
            b["cve"] = cve
            actions.append(b)
    out["actions"] = actions
    variant = f"m{m}-s{seed}" + ("-kev50" if kev_share is not None else "") + ("-shared" if shared else "")
    out["scenario_id"] = f"{data['scenario_id']}-V-{variant}"
    out["description"] = (f"Group V: {data['scenario_id']} with {m} CVE(s) per vulnerability slot, "
                          f"seed {seed}, rule {RULE}, snapshot {snapshot.id}"
                          + (f", KEV share {kev_share}" if kev_share is not None else "")
                          + (", shared per exploit" if shared else "") + ".")
    out["cve_assignment"] = {"rule": RULE, "snapshot_id": snapshot.id, "m": m, "seed": seed,
                             "kev_share": kev_share, "shared": shared,
                             "slots": {f: chosen[f] for f in sorted(chosen)}}
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("scenarios", nargs="+")
    ap.add_argument("--m", default="1,2,3,5")
    ap.add_argument("--seeds", type=int, default=10)
    ap.add_argument("--kev-share", type=float, default=None)
    ap.add_argument("--shared", action="store_true")
    ap.add_argument("--snapshot", default="data/snapshots")
    ap.add_argument("--snapshot-name", default=None)
    ap.add_argument("--out", required=True)
    args = ap.parse_args(argv)
    snap = load_snapshot(args.snapshot, args.snapshot_name)
    pool = pools(snap)
    os.makedirs(args.out, exist_ok=True)
    files = {}
    for path in args.scenarios:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        base = os.path.splitext(os.path.basename(path))[0]
        for m in (int(x) for x in args.m.split(",")):
            for seed in range(args.seeds):
                v = assign(data, snap, m, seed, args.kev_share, args.shared, pool)
                name = f"{base}-m{m}-s{seed}.json"
                raw = (json.dumps(v, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
                with open(os.path.join(args.out, name), "wb") as fh:
                    fh.write(raw)
                files[name] = hashlib.sha256(raw).hexdigest()
    manifest = {"rule": RULE, "snapshot_id": snap.id, "sources": args.scenarios,
                "m": args.m, "seeds": args.seeds, "kev_share": args.kev_share,
                "shared": args.shared,
                "pool_sizes": {k: len(v) for k, v in pool.items()}, "files": files}
    with open(os.path.join(args.out, "MANIFEST.json"), "w", encoding="utf-8", newline="\n") as fh:
        json.dump(manifest, fh, indent=2, sort_keys=True)
        fh.write("\n")
    print(f"wrote {len(files)} scenarios to {args.out} (snapshot {snap.id})")


if __name__ == "__main__":
    main()
