# AAPEF — Automated Attack Path Execution Framework

A **simulation-only** research prototype that models red-team planning as a
deterministic **state-space search** problem over JSON scenario data, and
compares four search algorithms — **BFS, DFS, Dijkstra, Greedy Best-First** — plus an optional **A*** with an admissible heuristic.

Everything runs on in-memory scenario data. There are **no real exploits, OS
commands, VMs, network access, external attack tools, or AI/ML**. See
[`AAPEF_Research_Plan.md`](AAPEF_Research_Plan.md) (v0.4) for the full design.

## Requirements

- Python 3.10+ (standard library only at runtime; algorithms: BFS, DFS, Dijkstra, Greedy, A*)
- `pytest` for tests: `pip install -r requirements.txt`

## Layout

```
aapef/
  state.py       # State, canonical state_key, applicable/apply/successors (shared transition)
  scenario.py    # scenario JSON loading + validation
  search.py      # bfs, dfs, dijkstra, greedy, astar + heuristics
  simulate.py    # replay a path + validate against the goal
  benchmark.py   # run all algos, measure |V|,|E|, export CSV/JSON
  analyze.py     # RQ-derived metrics (cost/length gaps, effort coverage)
  cvss.py        # CVSS v3.1-derived action costs (recost)
  sensitivity.py # re-run algorithms over seeded action-order permutations
  cli.py         # command-line entry point
scenarios/       # scenario JSON files, benchmark configs, gen_rq3.sh / gen_cve.sh (+ meta/, cve_catalog.json, cvss/)
scen_gen.py      # scenario generator (config and cvss cost models) with a built-in reference oracle
scripts/         # reproduce.sh: rebuild every result in one command
reports/         # BaoCao_PhanTich.md: analysis of RQ1-RQ4
out/             # committed benchmark outputs (CSV/JSON)
tests/           # pytest suite
```

## Quick demo

One command, all algorithms, one scenario (shows that the shortest path is
not the cheapest one):

```bash
python -m aapef demo                                   # scenarios/medium-01.json
python -m aapef demo --scenario scenarios/trap-01.json # Greedy lured into the costliest route
```

## Reproduce every result

```bash
bash scripts/reproduce.sh            # tests + scenarios + all benchmarks + sensitivity
SKIP_GENERATE=1 bash scripts/reproduce.sh   # reuse the committed scenarios
```

On Windows run it from WSL (set `PYTHON=` to the interpreter). Deterministic
columns (path, L, C, E_n, E_e, |V|, |E|) are identical on every run; only the
timing columns (`runtime_ms`, `runtime_iqr_ms`, `measure_ms`) vary.

## Usage

Run one algorithm on one scenario:

```bash
python -m aapef solve --scenario scenarios/demo-small-01.json --algo dijkstra
```

Measure the full reachable state-space size |V|, |E| (a separate reference
step, kept out of each algorithm's runtime):

```bash
python -m aapef statespace --scenario scenarios/medium-01.json
```

Run the full benchmark and export results:

```bash
python -m aapef benchmark --config scenarios/benchmark_config.json \
    --scenarios-dir scenarios --out out
# -> out/results.csv, out/statespace.csv, out/benchmark.json, out/analysis.csv
```

After each benchmark a **goal check** prints, per scenario, which algorithms
reached the goal with a valid path. A scenario no algorithm solves is flagged
`UNREACHABLE` unless its id is listed under `expect_unreachable` in the config
(then it must stay unsolved). Add `--strict` to exit with code 1 on any flag,
e.g. to filter freshly written or generated scenarios.

Re-run every algorithm on seeded permutations of the action order (DFS and
tie-break sensitivity; uses the config's `seed`):

```bash
python -m aapef sensitivity --config scenarios/benchmark_config.json \
    --permutations 50 --out out
# -> out/order_sensitivity.csv
```

Scaling runs (RQ3) use a separate config with fewer runtime repeats, so they
don't mix with the main benchmark. Add larger scenario ids to it:

```bash
python -m aapef benchmark --config scenarios/benchmark_scaling.json --out out/scaling
```

Run the tests:

```bash
python -m pytest
```

## What the metrics mean (plan §4.1, §12)

| Metric | Meaning | Source |
|---|---|---|
| `num_actions` (L) | number of actions in the path | search |
| `total_cost` (C) | sum of configured action costs | search |
| `nodes_expanded` (E_n) | states expanded in one run | search |
| `edges_examined` (E_e) | successors examined in one run | search |
| `runtime_ms` (T) | median search-loop time over repeats | search |
| `path_found` / `path_valid` / `goal_reached` | distinct outcome flags | search / validation / simulation |

`|V|, |E|` describe the **whole** reachable state-space of a scenario; they are
**not** the same as `nodes_expanded` / `edges_examined`, which describe the work
of a single algorithm run (usually smaller, since lazy search stops at the goal).

## Design note: the state-space is a DAG

Action effects are **monotonic** — `set_access` only raises an access level and
`learn` only adds a fact; nothing lowers access or removes a fact. As a result
the reachable state-space contains **no true cycles** (every non-no-op edge
strictly grows the state). Duplicate states are still reached by different paths
(e.g. independent discoveries form a *diamond*); the `visited` set deduplicates
those. Termination is therefore guaranteed regardless, and the state-space
measurement would also handle genuine cycles safely if the effect model were
ever extended to allow them.

## Generated scenarios (RQ3 / robustness)

`scen_gen.py` builds scenarios in the same schema and checks them with its own
reference oracle (`--verify`, `--stats`). It has two cost models
(`--cost-model`):

- `config` (regression): seeded costs, shortcuts, decoys, a Greedy lure,
  unreachable / initial-goal kinds. Regenerated with `bash scenarios/gen_rq3.sh`.
- `cvss` (main): lab-01-style **source** scenarios whose exploit actions carry a
  `cve` and **no cost**; the roles come from `scenarios/cve_catalog.json`.
  Regenerated with `bash scenarios/gen_cve.sh`; costs are then computed by
  `python -m aapef recost` (`bash scripts/recost_all.sh`) into `scenarios/cvss/`.

```bash
bash scenarios/gen_rq3.sh        # PYTHON=... to pick the interpreter
bash scenarios/gen_cve.sh
bash scripts/recost_all.sh
python -m aapef benchmark --config scenarios/benchmark_scaling.json   --out out/scaling   --strict
python -m aapef benchmark --config scenarios/benchmark_generated.json --out out/generated --strict
python -m aapef benchmark --config scenarios/benchmark_cvss.json --scenarios-dir scenarios/cvss --out out/cvss --strict
```

Generator reference values live in `scenarios/meta/` (for `cvss` sources they
hold the structure and |V|, |E| only; C* exists after `recost`). Note: a CVE
source file cannot be benchmarked directly (no cost fields); use the copy in
`scenarios/cvss/`. Results and their limits of interpretation are in
`reports/Chuong_KetQua.md` and `reports/BaoCao_PhanTich.md` (sections 7-9).

## CVSS-derived costs (plan section 9.3)

Action costs are computed, not typed: `cost = round(10 * -ln(E/10))` with `E` the
CVSS v3.1 Exploitability score of a vector derived from the action's own
structure (`reachable` -> AV, highest required access -> PR; AC/UI defaults).
Per-action `cvss_override` is optional.

```bash
python -m aapef recost --out-dir scenarios/cvss scenarios/medium-01.json   # rewrite costs
bash scripts/recost_all.sh                                                 # every scenario in benchmark_cvss.json
python -m aapef benchmark --config scenarios/benchmark_cvss.json --scenarios-dir scenarios/cvss --out out/cvss --strict
python scripts/cvss_sensitivity.py                                         # sensitivity to the model's assumptions
```

Actions may instead name a real vulnerability with `cve`; its vector (incl. Scope) then comes
from `scenarios/cve_catalog.json` (NVD records, CISA KEV candidates). `scenarios/lab-01.json`
is a pilot scenario costed this way (its source has no cost fields; `recost` writes
`scenarios/cvss/lab-01.json`).

The original scenarios (hand-typed / seeded costs) are untouched and kept as a
regression set. See `reports/ThayDoi_ChiPhiCVSS.md` for what changed and why.
