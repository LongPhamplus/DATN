"""Check the role-from-vector rule against a manual classification (task 2.3).

Step 1, draw the sample (seeded, from the CVEs of a snapshot that have a CVSS v3
vector; half from KEV, half from outside KEV):
    python scripts/role_sample.py draw --n 80 --seed 1 --out reports/role_sample.csv

Step 2, the author fills the `manual_role` column (one of aapef.roles.ROLES, or
`other`) from the NVD description. Neither the vector nor the
rule's answer is in the file, so they cannot bias the label; `score` reads the
vectors from the same snapshot. Step 3, score the agreement:
    python scripts/role_sample.py score reports/role_sample.csv
"""

import argparse
import csv
import os
import random
import sys
from collections import Counter

sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir))

from aapef.data import load_snapshot  # noqa: E402
from aapef.roles import ROLES, role_from_vector, role_with_filter  # noqa: E402

FIELDS = ["cve", "manual_role", "nvd_url"]


def draw(args):
    snap = load_snapshot(args.snapshots, args.name)
    with_vec = [r for r in snap.cves.values() if r.vector]
    kev = sorted(r.id for r in with_vec if r.kev)
    other = sorted(r.id for r in with_vec if not r.kev)
    rng = random.Random(args.seed)
    picked = rng.sample(kev, args.n // 2) + rng.sample(other, args.n - args.n // 2)
    rng.shuffle(picked)
    with open(args.out, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, FIELDS)
        w.writeheader()
        for cid in picked:
            w.writerow({"cve": cid, "manual_role": "",
                        "nvd_url": f"https://nvd.nist.gov/vuln/detail/{cid}"})
    print(f"wrote {len(picked)} rows to {args.out} (snapshot {snap.id}, seed {args.seed})")


def score(args):
    snap = load_snapshot(args.snapshots, args.name)
    with open(args.csv, newline="", encoding="utf-8") as fh:
        rows = [r for r in csv.DictReader(fh) if r["manual_role"].strip()]
    if not rows:
        sys.exit("no row has a manual_role yet")
    bad = [r["manual_role"] for r in rows if r["manual_role"] not in ROLES + ("other",)]
    if bad:
        sys.exit(f"unknown manual_role values: {sorted(set(bad))}")
    for name, fn in (("rule", lambda rec: role_from_vector(rec.vector)),
                     ("rule + access filter",
                      lambda rec: role_with_filter(rec.vector, rec.vector_string))):
        pred = [fn(snap.cves[r["cve"]]) for r in rows]
        hits = sum(r["manual_role"] == p for r, p in zip(rows, pred))
        print(f"{name}: agreement {hits}/{len(rows)} = {hits / len(rows):.1%}")
        confusion = Counter((r["manual_role"], p) for r, p in zip(rows, pred))
        print("  manual -> predicted: count")
        for (m, p), c in sorted(confusion.items()):
            print(f"    {m:15s} -> {p:15s} {c}")


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("draw")
    d.add_argument("--snapshots", default="data/snapshots")
    d.add_argument("--name", default=None)
    d.add_argument("--n", type=int, default=80)
    d.add_argument("--seed", type=int, default=1)
    d.add_argument("--out", default="reports/role_sample.csv")
    s = sub.add_parser("score")
    s.add_argument("csv")
    s.add_argument("--snapshots", default="data/snapshots")
    s.add_argument("--name", default=None)
    args = ap.parse_args()
    draw(args) if args.cmd == "draw" else score(args)


if __name__ == "__main__":
    main()
