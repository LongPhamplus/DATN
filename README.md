# AAPEF — Automated Attack Path Execution Framework

A **simulation-only** research prototype that models red-team planning as a
deterministic **state-space search** problem over JSON scenario data, and
compares five search algorithms — **BFS, DFS, Dijkstra, Greedy Best-First and A\*** (admissible heuristic) — on path length, path cost, search effort and runtime.

Everything runs on in-memory scenario data. There are **no real exploits, OS
commands, VMs, network access, external attack tools, or AI/ML**. CVE and CVSS
data are used only as public scoring metadata. See
[`AAPEF_Research_Plan.md`](AAPEF_Research_Plan.md) for the full design.

## 1. Setup

Requirements: **Python 3.10+**. The framework itself uses only the standard
library; `pytest` is needed for the tests.

```bash
python3 -m venv .venv
. .venv/bin/activate              # Windows PowerShell: .venv\Scripts\Activate.ps1
pip install -r requirements.txt   # pytest
```

The helper scripts (`scripts/*.sh`, `scenarios/gen_*.sh`) are bash. On Windows
run them from **WSL** or Git Bash, and pick the interpreter with
`PYTHON=/path/to/python bash scripts/reproduce.sh`. Run every command from the
**repository root** (default paths such as `scenarios/cve_catalog.json` are
relative to it).

## 2. Quick start

```bash
python -m pytest -q                                  # 69 tests
python -m aapef demo                                 # all 5 algorithms on scenarios/medium-01.json
python -m aapef demo --scenario scenarios/cvss/lab-01.json
python -m aapef solve --scenario scenarios/cvss/lab-01.json --algo dijkstra
```

`demo` prints one row per algorithm (`L`, `C`, `E_n`, `E_e`, `T`, outcome flags,
the path) and notes when the shortest path is not the cheapest one (`L != C`).

## 3. Which scenarios and which cost model

Action costs come from one of two models. **Use the CVSS one for results.**

| | CVSS model (main) | Config model (regression) |
|---|---|---|
| Cost of an action | computed by `recost` from a CVSS v3.1 vector | typed by hand or drawn from a seed |
| Scenarios | `scenarios/cvss/*.json` | `scenarios/*.json` |
| Benchmark config | `scenarios/benchmark_cvss.json` | `benchmark_config.json`, `benchmark_scaling.json`, `benchmark_generated.json` |
| Outputs | `out/cvss/` | `out/`, `out/scaling/`, `out/generated/` |

How a cost is computed (`aapef/cvss.py`): `E = 8.22 × AV × AC × PR × UI` (CVSS
v3.1 Exploitability), `p = E / 10`, `cost = round(10 × −ln p)`. The vector comes
from either

- the **action's structure** (`reachable` → AV, highest required access → PR;
  AC and UI default to Low / None), optionally refined by `cvss_override`; or
- a **real CVE** named in the action's `cve` field, whose vector (including
  Scope) is read from `scenarios/cve_catalog.json` (NVD records, CISA KEV
  candidates).

Information-gathering actions (only `learn` effects) get a fixed `p = 0.9`
(cost 1). Details and assumptions: plan §9.2–9.3 and
`reports/ThayDoi_ChiPhiCVSS.md`.

## 4. Commands

All commands are `python -m aapef <command>`.

| Command | What it does |
|---|---|
| `demo [--scenario F] [--repeats N]` | one summary table for all algorithms |
| `solve --scenario F --algo {bfs,dfs,dijkstra,greedy,astar} [--repeats N]` | one algorithm, one scenario |
| `statespace --scenario F` | full reachable \|V\| and \|E\| (a separate reference step, kept out of runtimes) |
| `recost --out-dir D [options] F...` | rewrite scenario files with CVSS-derived costs |
| `benchmark --config C [--scenarios-dir D] [--out D] [--repeats N] [--strict]` | run all algorithms on all scenarios in a config, export CSV/JSON |
| `sensitivity --config C [--scenarios-dir D] [--out D] [--permutations N]` | re-run algorithms over seeded permutations of the action order |

`recost` options: `--scale` (default 10), `--p-norm` (10), `--discovery-p`
(0.9), `--default-ac {L,H}`, `--default-ui {N,R}`, `--catalog` (default
`scenarios/cve_catalog.json`, used when a scenario has `cve` actions).

### Recost one scenario, then run it

```bash
python -m aapef recost --out-dir scenarios/cvss scenarios/medium-01.json
python -m aapef demo --scenario scenarios/cvss/medium-01.json
```

### Run the main (CVSS) benchmark

```bash
bash scripts/recost_all.sh                     # (re)writes every scenario listed in benchmark_cvss.json into scenarios/cvss/
python -m aapef benchmark --config scenarios/benchmark_cvss.json \
    --scenarios-dir scenarios/cvss --out out/cvss --strict
python -m aapef sensitivity --config scenarios/benchmark_cvss.json \
    --scenarios-dir scenarios/cvss --permutations 50 --out out/cvss
python scripts/cvss_sensitivity.py             # sensitivity to the cost-model assumptions
```

### Run the config-model (regression) benchmarks

```bash
python -m aapef benchmark --config scenarios/benchmark_config.json    --scenarios-dir scenarios --out out
python -m aapef benchmark --config scenarios/benchmark_scaling.json   --scenarios-dir scenarios --out out/scaling
python -m aapef benchmark --config scenarios/benchmark_generated.json --scenarios-dir scenarios --out out/generated
```

Always pass `--config`: without it `benchmark` loads every JSON file in the
scenarios directory, including CVE-source files that have no costs.

After each benchmark a **goal check** prints, per scenario, which algorithms
reached the goal with a valid path. A scenario no algorithm solves is flagged
`UNREACHABLE` unless its id is listed under `expect_unreachable` in the config.
`--strict` exits with code 1 on any flag.

## 5. Generating scenarios

`scen_gen.py` writes scenario JSON and checks it with its own reference oracle
(`--verify`, `--stats`). It has two cost models (`--cost-model`):

- `config` — seeded costs, shortcuts, decoys, a Greedy lure, unreachable /
  initial-goal kinds. The committed set is regenerated with
  `bash scenarios/gen_rq3.sh`.
- `cvss` — lab-01-style **source** scenarios: exploit actions carry a `cve`
  and **no `cost`**; roles come from `scenarios/cve_catalog.json`. The
  committed set is regenerated with `bash scenarios/gen_cve.sh`.

```bash
bash scenarios/gen_rq3.sh        # config-model scenarios (+ scenarios/meta/*.meta.json)
bash scenarios/gen_cve.sh        # CVE-source scenarios
bash scripts/recost_all.sh       # compute costs -> scenarios/cvss/
```

Generation is deterministic (seeded). Scenario ids carry the measured \|V\|.
`scenarios/meta/` holds the generator's reference values; for CVE sources it
holds structure and \|V\|, \|E\| only, because C\* exists only after `recost`.

A CVE-source file cannot be benchmarked directly. Use the recosted copy in
`scenarios/cvss/`.

## 6. Reproduce every result

```bash
bash scripts/reproduce.sh                   # 8 steps: tests, regenerate scenarios, all benchmarks, sensitivities
SKIP_GENERATE=1 bash scripts/reproduce.sh   # reuse the committed scenarios
```

The full run takes several minutes (the largest scenario has 16 128 states).
Deterministic columns (path, L, C, E_n, E_e, \|V\|, \|E\|) are identical on every
run; only the timing columns (`runtime_ms`, `runtime_iqr_ms`, `measure_ms`) vary.

## 7. Outputs

| File | Content |
|---|---|
| `results.csv` | per scenario × algorithm: found/valid/goal flags, L, C, E_n, E_e, runtime median and IQR |
| `analysis.csv` | gaps to the optimum (`cost_gap`, `cost_ratio`, `length_gap`), effort relative to BFS, coverage of \|V\|, \|E\| |
| `statespace.csv` | \|V\|, \|E\| and the time spent measuring them |
| `benchmark.json` | the same rows plus the paths |
| `order_sensitivity.csv` | spread of path, L, C, E_n over action-order permutations |
| `assumption_sensitivity.csv` | (`out/cvss/` only) effect of the cost-model assumptions |

C\* is taken from **Dijkstra's** cost and L\* from **BFS's** length
(`aapef/analyze.py`); each is used as the reference for that quantity only.

## 8. What the metrics mean (plan §4.1, §12)

| Metric | Meaning | Source |
|---|---|---|
| `num_actions` (L) | number of actions in the path | search |
| `total_cost` (C) | sum of action costs (CVSS-derived in the main benchmark) | search |
| `nodes_expanded` (E_n) | states expanded in one run | search |
| `edges_examined` (E_e) | successors examined in one run | search |
| `runtime_ms` (T) | median search-loop time over repeats | search |
| `path_found` / `path_valid` / `goal_reached` | distinct outcome flags | search / validation / simulation |

`|V|, |E|` describe the **whole** reachable state-space of a scenario; they are
**not** the same as `nodes_expanded` / `edges_examined`, which describe the work
of a single algorithm run (usually smaller, since lazy search stops at the goal).

## 9. Troubleshooting

| Message / symptom | Cause and fix |
|---|---|
| `no 'cost' field. This looks like a CVE-source scenario` | you loaded a source file; run `recost` and use the copy in `scenarios/cvss/` |
| `cve ... needs a CVE catalog` | run from the repo root or pass `--catalog scenarios/cve_catalog.json` |
| `... is not in the catalog` | add the CVE (with its NVD vector) to `scenarios/cve_catalog.json` |
| goal check flags `UNREACHABLE` | no algorithm reached the goal; fix the scenario or list it under `expect_unreachable` |
| `git status` shows every file modified (WSL) | line-ending mismatch between the Windows checkout and Linux git; use the same git that made the checkout |

## 10. Layout

```
aapef/
  state.py       # State, canonical state_key, applicable/apply/successors (shared transition)
  scenario.py    # scenario JSON loading + validation
  search.py      # bfs, dfs, dijkstra, greedy, astar + heuristics
  simulate.py    # replay a path + validate against the goal
  benchmark.py   # run all algos, measure |V|,|E|, goal check, export CSV/JSON
  analyze.py     # RQ-derived metrics (cost/length gaps, effort coverage)
  cvss.py        # CVSS v3.1-derived action costs, CVE catalog, recost
  sensitivity.py # re-run algorithms over seeded action-order permutations
  cli.py         # command-line entry point
scenarios/       # scenarios (config model), cvss/ (recosted), cve_catalog.json, benchmark_*.json, gen_*.sh, meta/
scen_gen.py      # scenario generator (config and cvss cost models) with a reference oracle
scripts/         # reproduce.sh, recost_all.sh, cvss_sensitivity.py
reports/         # analysis reports (see reports/Chuong_KetQua.md)
out/             # committed benchmark outputs (CSV/JSON)
tests/           # pytest suite
```

## 11. Design note: the state-space is a DAG

Action effects are **monotonic** — `set_access` only raises an access level and
`learn` only adds a fact; nothing lowers access or removes a fact. As a result
the reachable state-space contains **no true cycles** (every non-no-op edge
strictly grows the state). Duplicate states are still reached by different paths
(e.g. independent discoveries form a *diamond*); the `visited` set deduplicates
those. Termination is therefore guaranteed regardless, and the state-space
measurement would also handle genuine cycles safely if the effect model were
ever extended to allow them. Actions whose effect changes nothing (no-ops) are
never edges.
