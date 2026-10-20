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
  sensitivity.py # re-run algorithms over seeded action-order permutations
  cli.py         # command-line entry point
scenarios/       # scenario JSON files, benchmark configs, gen_rq3.sh (+ meta/)
scen_gen.py      # seeded scenario generator with a built-in reference oracle
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

`scen_gen.py` builds scenarios in the same schema (seeded costs, shortcuts,
decoys, a Greedy lure, unreachable / initial-goal kinds) and checks them with
its own reference oracle (`--verify`, `--stats`). The committed set is
regenerated deterministically with:

```bash
bash scenarios/gen_rq3.sh        # PYTHON=... to pick the interpreter
python -m aapef benchmark --config scenarios/benchmark_scaling.json   --out out/scaling   --strict
python -m aapef benchmark --config scenarios/benchmark_generated.json --out out/generated --strict
```

Generator reference values live in `scenarios/meta/`. Results and their limits
of interpretation are in `reports/BaoCao_PhanTich.md` (sections 7-9).
