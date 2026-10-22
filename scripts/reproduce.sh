#!/usr/bin/env bash
# Reproduces every result (config-cost experiments and the CVSS cost model) from scratch.
# Run from the repo root:   bash scripts/reproduce.sh
#   PYTHON=/path/to/python bash scripts/reproduce.sh    (pick the interpreter)
#   SKIP_GENERATE=1 bash scripts/reproduce.sh           (reuse committed scenarios)
# Needs only the Python standard library at runtime; pytest for step 1.
# Outputs go to out/ (results, state-space sizes, analysis, order sensitivity).
set -euo pipefail
PY=${PYTHON:-python3}
export PYTHONDONTWRITEBYTECODE=1

step() { printf '\n==> %s\n' "$*"; }

step "1/8 tests"
$PY -m pytest -q -p no:cacheprovider

if [ -z "${SKIP_GENERATE:-}" ]; then
  step "2/8 regenerate generated scenarios (deterministic)"
  PYTHON=$PY bash scenarios/gen_rq3.sh
else
  step "2/8 regenerate scenarios (skipped)"
fi

step "3/8 main benchmark: 4 hand-written scenarios (RQ1, RQ2, RQ4)"
$PY -m aapef benchmark --config scenarios/benchmark_config.json --out out --strict

step "4/8 scaling benchmark (RQ3)"
$PY -m aapef benchmark --config scenarios/benchmark_scaling.json --out out/scaling --strict

step "5/8 generated scenarios: traps, cycles, unreachable, initial-goal"
$PY -m aapef benchmark --config scenarios/benchmark_generated.json --out out/generated --strict

step "6/8 action-order sensitivity (50 permutations, seed from config)"
$PY -m aapef sensitivity --config scenarios/benchmark_config.json --permutations 50 --out out
$PY -m aapef sensitivity --config scenarios/benchmark_generated.json --permutations 50 --out out/generated

step "7/8 CVSS cost model: recost scenarios, benchmark, order sensitivity"
bash scripts/recost_all.sh
$PY -m aapef benchmark --config scenarios/benchmark_cvss.json --scenarios-dir scenarios/cvss --out out/cvss --strict
$PY -m aapef sensitivity --config scenarios/benchmark_cvss.json --scenarios-dir scenarios/cvss --permutations 50 --out out/cvss

step "8/8 sensitivity to the published CVSS assumptions"
$PY scripts/cvss_sensitivity.py --config scenarios/benchmark_cvss.json --out out/cvss/assumption_sensitivity.csv

printf '\nDone. See out/, out/scaling/, out/generated/, out/cvss/ and reports/\n'
