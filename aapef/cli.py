"""Command-line entry point (plan §11).

Subcommands:
    solve       Run one algorithm on one scenario and print the result.
    statespace  Measure |V|, |E| for a scenario.
    benchmark   Run all algorithms over several scenarios and export CSV/JSON.
    sensitivity Re-run algorithms on seeded permutations of the action order.
"""

import argparse
import glob
import json
import os
import sys

from .analyze import analyze, write_analysis
from .benchmark import (
    goal_check, measure_state_space, run_benchmark, run_search, write_results,
)
from .scenario import ScenarioError, load_scenario
from .search import ALGORITHMS
from .sensitivity import order_sensitivity, write_sensitivity


def _load(path):
    try:
        return load_scenario(path)
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(2)


def cmd_solve(args):
    scenario = _load(args.scenario)
    row = run_search(scenario, args.algo, runtime_repeats=args.repeats)
    print(f"scenario : {row['scenario_id']}")
    print(f"algorithm: {row['algorithm']}")
    if row["path_found"]:
        path = row["path"]
        print(f"path     : {path if path else '[] (initial state already at goal)'}")
    else:
        print("path     : NONE (no path to goal)")
    print(f"path_found={row['path_found']} path_valid={row['path_valid']} "
          f"goal_reached={row['goal_reached']}")
    print(f"num_actions={row['num_actions']} total_cost={row['total_cost']}")
    print(f"nodes_expanded={row['nodes_expanded']} "
          f"edges_examined={row['edges_examined']} "
          f"runtime_ms={row['runtime_ms']} (IQR {row['runtime_iqr_ms']})")


def cmd_statespace(args):
    scenario = _load(args.scenario)
    info = measure_state_space(scenario)
    print(f"scenario   : {info['scenario_id']}")
    print(f"|V| states : {info['num_states']}")
    print(f"|E| edges  : {info['num_edges']}")


def _load_run_config(args):
    """Resolve (scenarios, config dict) from --config or --scenarios-dir.

    With --config, scenario ids are looked up in --scenarios-dir. Without it,
    every *.json in --scenarios-dir is loaded except *config* files.
    """
    cfg = {}
    if args.config:
        with open(args.config, "r", encoding="utf-8") as fh:
            cfg = json.load(fh)
        paths = [os.path.join(args.scenarios_dir, f"{sid}.json")
                 for sid in cfg.get("scenarios", [])]
    else:
        paths = sorted(p for p in glob.glob(os.path.join(args.scenarios_dir, "*.json"))
                       if "config" not in os.path.basename(p))
    scenarios = [_load(p) for p in paths]
    if not scenarios:
        print("error: no scenarios found", file=sys.stderr)
        raise SystemExit(2)
    return scenarios, cfg


def cmd_benchmark(args):
    scenarios, cfg = _load_run_config(args)
    algorithms = cfg.get("algorithms", list(ALGORITHMS))
    repeats = cfg.get("runtime_repeats", args.repeats)

    results, statespace = run_benchmark(scenarios, algorithms, repeats)
    write_results(results, statespace, args.out)
    write_analysis(analyze(results, statespace), args.out)
    print(f"ran {len(scenarios)} scenario(s) x {len(algorithms)} algorithm(s)")
    print(f"wrote results to {os.path.abspath(args.out)}/"
          " (results.csv, statespace.csv, benchmark.json, analysis.csv)")

    checks = goal_check(results, cfg.get("expect_unreachable", []))
    problems = [c for c in checks
                if c["status"] not in ("ok", "expected-unreachable")]
    print("goal check:")
    for c in checks:
        by = f" (reached by: {c['reached_by']})" if c["reached_by"] else ""
        print(f"  {c['status']:<22} {c['scenario_id']}{by}")
    if problems:
        print(f"warning: {len(problems)} scenario(s) did not behave as expected; "
              "fix them, replace them, or list intentional no-goal scenarios "
              "under 'expect_unreachable' in the config", file=sys.stderr)
        if args.strict:
            raise SystemExit(1)


def cmd_sensitivity(args):
    scenarios, cfg = _load_run_config(args)
    algorithms = cfg.get("algorithms", list(ALGORITHMS))
    seed = cfg.get("seed", args.seed)
    rows = []
    for scenario in scenarios:
        rows.extend(order_sensitivity(scenario, algorithms,
                                      args.permutations, seed))
    write_sensitivity(rows, args.out)
    print(f"ran {len(scenarios)} scenario(s) x {len(algorithms)} algorithm(s)"
          f" x {args.permutations + 1} action orders (seed {seed})")
    print(f"wrote {os.path.abspath(os.path.join(args.out, 'order_sensitivity.csv'))}")


def build_parser():
    parser = argparse.ArgumentParser(prog="aapef", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    p_solve = sub.add_parser("solve", help="run one algorithm on one scenario")
    p_solve.add_argument("--scenario", required=True)
    p_solve.add_argument("--algo", required=True, choices=ALGORITHMS)
    p_solve.add_argument("--repeats", type=int, default=5)
    p_solve.set_defaults(func=cmd_solve)

    p_ss = sub.add_parser("statespace", help="measure |V|, |E| of a scenario")
    p_ss.add_argument("--scenario", required=True)
    p_ss.set_defaults(func=cmd_statespace)

    p_bench = sub.add_parser("benchmark", help="run all algorithms, export CSV/JSON")
    p_bench.add_argument("--config", help="benchmark_config.json with scenario ids")
    p_bench.add_argument("--scenarios-dir", default="scenarios")
    p_bench.add_argument("--out", default="out")
    p_bench.add_argument("--repeats", type=int, default=30)
    p_bench.add_argument("--strict", action="store_true",
                         help="exit 1 if a scenario fails the goal check")
    p_bench.set_defaults(func=cmd_benchmark)

    p_sens = sub.add_parser("sensitivity",
                            help="re-run algorithms on permuted action orders")
    p_sens.add_argument("--config", help="benchmark_config.json with scenario ids")
    p_sens.add_argument("--scenarios-dir", default="scenarios")
    p_sens.add_argument("--out", default="out")
    p_sens.add_argument("--permutations", type=int, default=20)
    p_sens.add_argument("--seed", type=int, default=42,
                        help="used when the config has no 'seed'")
    p_sens.set_defaults(func=cmd_sensitivity)

    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
