#!/usr/bin/env bash
# Reproduces every result (search benchmarks, CVSS cost model, patch-policy
# experiments of groups N and V) from scratch.
# Run from the repo root:   bash scripts/reproduce.sh
#   PYTHON=/path/to/python bash scripts/reproduce.sh    (pick the interpreter)
#   SKIP_GENERATE=1 bash scripts/reproduce.sh           (reuse committed scenarios)
# Needs only the Python standard library at runtime; pytest for step 1.
# Outputs go to out/ (results, state-space sizes, analysis, order sensitivity)
# and out/policies/ (patch policies). Group V takes about 1 hour on 16 cores
# (JOBS=..., default 16); POLICY_SENSITIVITY=1 also runs the sensitivity grid.
set -euo pipefail
PY=${PYTHON:-python3}
export PYTHONDONTWRITEBYTECODE=1

step() { printf '\n==> %s\n' "$*"; }

step "1/10 tests"
$PY -m pytest -q -p no:cacheprovider

if [ -z "${SKIP_GENERATE:-}" ]; then
  step "2/10 regenerate generated scenarios (deterministic)"
  PYTHON=$PY bash scenarios/gen_rq3.sh
  PYTHON=$PY bash scenarios/gen_cve.sh
else
  step "2/10 regenerate scenarios (skipped)"
fi

step "3/10 main benchmark: 4 hand-written scenarios (RQ1, RQ2, RQ4)"
$PY -m aapef benchmark --config scenarios/benchmark_config.json --out out --strict

step "4/10 scaling benchmark (RQ3)"
$PY -m aapef benchmark --config scenarios/benchmark_scaling.json --out out/scaling --strict

step "5/10 generated scenarios: traps, cycles, unreachable, initial-goal"
$PY -m aapef benchmark --config scenarios/benchmark_generated.json --out out/generated --strict

step "6/10 action-order sensitivity (50 permutations, seed from config)"
$PY -m aapef sensitivity --config scenarios/benchmark_config.json --permutations 50 --out out
$PY -m aapef sensitivity --config scenarios/benchmark_generated.json --permutations 50 --out out/generated

step "7/10 CVSS cost model: recost scenarios, benchmark, order sensitivity"
bash scripts/recost_all.sh
$PY -m aapef benchmark --config scenarios/benchmark_cvss.json --scenarios-dir scenarios/cvss --out out/cvss --strict
$PY -m aapef sensitivity --config scenarios/benchmark_cvss.json --scenarios-dir scenarios/cvss --permutations 50 --out out/cvss

step "8/10 sensitivity to the published CVSS assumptions"
$PY scripts/cvss_sensitivity.py --config scenarios/benchmark_cvss.json --out out/cvss/assumption_sensitivity.csv

step "9/10 patch policies, group N (NASim structures, models native and cvss)"
$PY -m aapef.experiment scenarios/small.json scenarios/small-linear.json \
    scenarios/medium-multi-site.json scenarios/medium-single-site.json \
    --models native,cvss --out out/policies/N
$PY -m aapef.policy_stats out/policies/N/summary.csv --out out/policies/N/stats > /dev/null

step "10/10 patch policies, group V (CVEs from snapshot 2026-10-28; reports/QuyTac_GanCVE.md)"
PY=$PY bash scripts/run_group_v.sh
for m in 1 2 3 5; do
  $PY -m aapef.policy_stats out/policies/V/*-m$m/summary.csv --out out/policies/V/stats-m$m > /dev/null
done
if [ -n "${POLICY_SENSITIVITY:-}" ]; then
  PY=$PY bash scripts/run_group_v.sh --sensitivity
fi

printf '\nDone. See out/, out/scaling/, out/generated/, out/cvss/, out/policies/ and reports/\n'
