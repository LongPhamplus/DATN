#!/usr/bin/env bash
# Regenerates the CVE-source scenarios (scen_gen.py --cost-model cvss).
# These files carry `cve` and NO cost fields: `python -m aapef recost`
# (scripts/recost_all.sh) computes costs from scenarios/cve_catalog.json and
# writes the benchmarkable copies to scenarios/cvss/.
# Parameters were fixed from structure only (chain length and |V| bands),
# before any cost was computed. Deterministic. Run from the repo root:
#   bash scenarios/gen_cve.sh
# Scenario ids carry the measured |V|. --hosts 4 with no dead-ends or decoys
# has the same structure as scenarios/lab-01.json (|V| = 16, |E| = 44).
set -euo pipefail
PY=${PYTHON:-python3}
OUT=scenarios
META=scenarios/meta
mkdir -p "$META"

gen() { # id, then generator flags
  local id=$1; shift
  $PY scen_gen.py --id "$id" --out "$OUT/$id.json" --verify --stats --seed 42 \
      --cost-model cvss "$@" >/dev/null
  mv "$OUT/$id.meta.json" "$META/$id.meta.json"
  echo "generated $id"
}

# Chain-length series (no dead-ends, no decoys); compare with lab-01 (4 hosts).
gen cve-h5-v24 --hosts 5 --deadends 0
gen cve-h6-v32 --hosts 6 --deadends 0
gen cve-h7-v40 --hosts 7 --deadends 0

# Size ladder (4 hosts): dead-ends ~x3 and decoys ~x2 per unit.
gen cve-size-v112   --hosts 4 --deadends 1 --decoys 2
gen cve-size-v336   --hosts 4 --deadends 2 --decoys 2
gen cve-size-v1024  --hosts 4 --deadends 0 --decoys 6
gen cve-size-v4032  --hosts 4 --deadends 3 --decoys 4
gen cve-size-v16128 --hosts 4 --deadends 3 --decoys 6

# Edge cases.
gen cve-unreachable-v21  --hosts 4 --deadends 2 --kind unreachable
gen cve-initial-goal-v10 --hosts 4 --deadends 1 --kind initial-goal
gen cve-cycles-v72       --hosts 5 --deadends 1 --cycles
