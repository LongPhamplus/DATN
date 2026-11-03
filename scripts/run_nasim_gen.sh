#!/usr/bin/env bash
# Group G: networks from NASim's own generator, without and with real CVEs.
# Run from the repo root in WSL:   bash scripts/run_nasim_gen.sh [--bench]
#   1. export 7 generated benchmarks x seeds 0-2 to data/nasim_gen/*.yaml
#   2. convert with nasim2aapef.py -> scenarios/G/
#   3. assign CVEs (m = 1, 3; one CVE seed) -> scenarios/G_cve/
#   4. with --bench: scripts/bench_nasim_gen.py -> out/nasim_gen/
set -euo pipefail
NASIM_PY=${NASIM_PY:-$HOME/.venvs/nasim/bin/python}
PY=${PY:-$HOME/.venvs/aapef/bin/python}
FAMILIES="tiny-gen small-gen medium-gen large-gen huge-gen pocp-1-gen pocp-2-gen"
for b in $FAMILIES; do
  for s in 0 1 2; do
    $NASIM_PY scripts/nasim_gen_export.py --benchmark "$b" --seed "$s" -o "data/nasim_gen/$b-s$s.yaml"
    $PY nasim2aapef.py "data/nasim_gen/$b-s$s.yaml" -o "scenarios/G/$b-s$s.json" --id "nasim-$b-s$s"
  done
done
$PY scripts/assign_cves.py scenarios/G/*.json --m 1,3 --seeds 1 --out scenarios/G_cve
if [ "${1:-}" = "--bench" ]; then
  $PY scripts/bench_nasim_gen.py --out out/nasim_gen --workers 6 --timeout 180 --mem-gb 2
fi
