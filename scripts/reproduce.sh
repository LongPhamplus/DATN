#!/usr/bin/env bash
# Reproduces every result in reports/BaoCao_PhanTich.md from scratch.
# Run from the repo root:   bash scripts/reproduce.sh
#   PYTHON=/path/to/python bash scripts/reproduce.sh    (pick the interpreter)
#   SKIP_GENERATE=1 bash scripts/reproduce.sh           (reuse committed scenarios)
# Needs only the Python standard library at runtime; pytest for step 1.
# Outputs go to out/ (results, state-space sizes, analysis, order sensitivity).
set -euo pipefail
PY=${PYTHON:-python3}
export PYTHONDONTWRITEBYTECODE=1

step() { printf '\n==> %s\n' "$*"; }

step "1/6 tests"
$PY -m pytest -q -p no:cacheprovider

if [ -z "${SKIP_GENERATE:-}" ]; then
  step "2/6 regenerate generated scenarios (deterministic)"
  PYTHON=$PY bash scenarios/gen_rq3.sh
else
  step "2/6 regenerate scenarios (skipped)"
fi

step "3/6 main benchmark: 4 hand-written scenarios (RQ1, RQ2, RQ4)"
$PY -m aapef benchmark --config scenarios/benchmark_config.json --out out --strict

step "4/6 scaling benchmark (RQ3)"
$PY -m aapef benchmark --config scenarios/benchmark_scaling.json --out out/scaling --strict

step "5/6 generated scenarios: traps, cycles, unreachable, initial-goal"
$PY -m aapef benchmark --config scenarios/benchmark_generated.json --out out/generated --strict

step "6/6 action-order sensitivity (50 permutations, seed from config)"
$PY -m aapef sensitivity --config scenarios/benchmark_config.json --permutations 50 --out out
$PY -m aapef sensitivity --config scenarios/benchmark_generated.json --permutations 50 --out out/generated

printf '\nDone. See out/, out/scaling/, out/generated/ and reports/BaoCao_PhanTich.md\n'
