#!/usr/bin/env bash
# Group-V experiment grid (reports/QuyTac_GanCVE.md §5-6).
#
#   scripts/run_group_v.sh                      main run  -> out/policies/V/
#   scripts/run_group_v.sh --sensitivity        the pre-registered sensitivity runs
#
# Scenarios are regenerated with scripts/assign_cves.py and checked against the
# committed scenarios/<dir>/MANIFEST.json (a new variant writes its manifest the
# first time). One job per (variant, structure, m); jobs run in parallel.
set -euo pipefail
PY=${PY:-python}
JOBS=${JOBS:-16}
STRUCTS="small small-linear medium-single-site medium-multi-site"
SOURCES=$(for s in $STRUCTS; do printf 'scenarios/%s.json ' "$s"; done)

# regen <scenario dir> [assign_cves flags...]
regen() {
  local dir=$1; shift
  local saved=""
  if [ -f "$dir/MANIFEST.json" ]; then saved=$(mktemp); cp "$dir/MANIFEST.json" "$saved"; fi
  $PY scripts/assign_cves.py $SOURCES --m 1,2,3,5 --seeds 10 --out "$dir" "$@" >/dev/null
  if [ -n "$saved" ]; then
    $PY - "$saved" "$dir/MANIFEST.json" <<'PY'
import json, sys
old, new = (json.load(open(p)) for p in sys.argv[1:3])
assert old == new, "regenerated scenarios differ from the committed MANIFEST.json"
print(f"{sys.argv[2]}: {len(new['files'])} scenarios match the committed manifest")
PY
    rm -f "$saved"
  else
    echo "$dir/MANIFEST.json written (new variant)"
  fi
}

# job lines: <scenario dir> <out dir> <structure> <m> <experiment flags...>
jobs_for() {
  local scen=$1 out=$2; shift 2
  for s in $STRUCTS; do for m in 1 2 3 5; do echo "$scen $out $s $m $*"; done; done
}

run_jobs() {
  xargs -P "$JOBS" -L 1 bash -c '
    scen=$0 out=$1 s=$2 m=$3; shift 3   # bash -c puts the first word in $0
    mkdir -p "$out"
    '"$PY"' -m aapef.experiment "$scen/$s-m$m"-s*.json --snapshot data/snapshots \
        --out "$out/$s-m$m" "$@" > "$out/log-$s-m$m.txt" 2>&1 && echo "done $out $s m=$m"'
}

if [ "${1:-}" = "--sensitivity" ]; then
  regen scenarios/V
  regen scenarios/V_kev50 --kev-share 0.5
  regen scenarios/V_shared --shared
  F="--seeds 50"   # sensitivity runs use 50 random-policy seeds (runtime)
  {
    jobs_for scenarios/V        out/policies/V_K15      --models cvss,epss,kev $F --K 15
    jobs_for scenarios/V_kev50  out/policies/V_kev50    --models cvss,epss,kev $F
    jobs_for scenarios/V_shared out/policies/V_shared   --models cvss,epss,kev $F
    jobs_for scenarios/V        out/policies/V_pkev050  --models kev --p-kev 0.5 $F
    jobs_for scenarios/V        out/policies/V_pkev099  --models kev --p-kev 0.99 $F
  } | run_jobs
else
  regen scenarios/V
  jobs_for scenarios/V out/policies/V --models cvss,epss,kev --seeds 200 | run_jobs
fi
