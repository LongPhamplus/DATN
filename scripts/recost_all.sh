#!/usr/bin/env bash
# Rewrites every scenario listed in scenarios/benchmark_cvss.json with
# CVSS-derived costs into scenarios/cvss/ (originals are left untouched).
# Run from the repo root:   bash scripts/recost_all.sh
set -euo pipefail
PY=${PYTHON:-python3}
FILES=$($PY - <<'PYEOF'
import json
cfg = json.load(open("scenarios/benchmark_cvss.json", encoding="utf-8"))
print(" ".join(f"scenarios/{sid}.json" for sid in cfg["scenarios"]))
PYEOF
)
$PY -m aapef recost --out-dir scenarios/cvss $FILES
