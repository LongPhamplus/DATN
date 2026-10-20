#!/usr/bin/env bash
# Regenerates the generated scenarios used for RQ3 (scaling) and robustness
# runs. Deterministic: same command -> same files. Run from the repo root:
#   bash scenarios/gen_rq3.sh
# Scenario ids carry the measured |V| (not the target).
set -euo pipefail
PY=${PYTHON:-python3}
OUT=scenarios
META=scenarios/meta
mkdir -p "$META"

gen() { # id, then generator flags
  local id=$1; shift
  $PY scen_gen.py --id "$id" --out "$OUT/$id.json" --verify --stats --seed 42 "$@" >/dev/null
  mv "$OUT/$id.meta.json" "$META/$id.meta.json"
  echo "generated $id"
}

# Size ladder (hosts=5): |V| grows via dead-ends (~x3) and decoys (~x2).
gen size-v132   --hosts 5 --deadends 1 --decoys 1
gen size-v352   --hosts 5 --deadends 0 --decoys 4
gen size-v1026  --hosts 5 --deadends 4 --decoys 0
gen size-v3024  --hosts 5 --deadends 3 --decoys 3
gen size-v11264 --hosts 5 --deadends 0 --decoys 9

# Robustness / research-question scenarios.
gen trap-01 --hosts 5 --greedy-trap
gen trap-02 --hosts 7 --deadends 2 --shortcuts 3 --greedy-trap --seed 11
gen cycles-01 --hosts 7 --deadends 1 --shortcuts 2 --cycles
gen unreachable-02 --hosts 5 --deadends 2 --kind unreachable
gen initial-goal-02 --hosts 5 --deadends 1 --kind initial-goal
