#!/usr/bin/env bash
# Group-V experiment grid (reports/QuyTac_GanCVE.md §5): one job per
# (structure, m), run in parallel; results in out/policies/V/<structure>-m<m>/.
# Regenerates the scenarios first and checks them against scenarios/V/MANIFEST.json.
set -euo pipefail
PY=${PY:-python}
JOBS=${JOBS:-16}
$PY scripts/assign_cves.py scenarios/small.json scenarios/small-linear.json \
    scenarios/medium-single-site.json scenarios/medium-multi-site.json \
    --m 1,2,3,5 --seeds 10 --out scenarios/V >/dev/null
$PY - <<'PY'
import hashlib, json, os
m = json.load(open("scenarios/V/MANIFEST.json"))
bad = [f for f, h in m["files"].items()
       if hashlib.sha256(open(os.path.join("scenarios/V", f), "rb").read()).hexdigest() != h]
assert not bad, f"scenarios differ from the manifest: {bad[:3]}"
print(f"{len(m['files'])} scenarios match the manifest")
PY
for s in small small-linear medium-single-site medium-multi-site; do
  for m in 1 2 3 5; do echo "$s $m"; done
done | xargs -P "$JOBS" -n 2 sh -c '
  '"$PY"' -m aapef.experiment scenarios/V/"$0"-m"$1"-s*.json --models cvss,epss,kev \
      --snapshot data/snapshots --seeds 200 --out out/policies/V/"$0"-m"$1" \
      > out/policies/V/log-"$0"-m"$1".txt 2>&1 && echo "done $0 m=$1"'
