"""Write a scenario from NASim's own generator as a NASim .yaml file.

NASim (0.12.0) builds generated scenarios (tiny-gen ... pocp-2-gen, or
generate_scenario with free parameters) in memory only and has no YAML writer.
This script writes the same keys as the static files in data/nasim/, so the
unchanged converter nasim2aapef.py reads it like any other NASim file:

    ~/.venvs/nasim/bin/python scripts/nasim_gen_export.py --benchmark medium-gen \
        --seed 0 -o data/nasim_gen/medium-gen-s0.yaml
    ~/.venvs/nasim/bin/python scripts/nasim_gen_export.py --hosts 60 --services 6 \
        --os 2 --processes 2 --restrictiveness 3 --seed 0 -o data/nasim_gen/h60-s0.yaml

Needs the NASim venv. NASim imports tkinter for its GUI on import; when it is
missing (python3-tk not installed) an empty stub is put in its place, since the
generator does not use the GUI.

NASim's generator is only reproducible with a fixed PYTHONHASHSEED (see
main); the script sets it to 0.

The generator puts no per-host firewall on any host; the script stops if one
appears, because nasim2aapef.py would ignore it.
"""

import argparse
import os
import sys
import types

ACCESS = {1: "user", 2: "root"}


def _import_nasim():
    try:
        import tkinter  # noqa: F401
    except ImportError:
        sys.modules["tkinter"] = types.ModuleType("tkinter")
    import warnings
    warnings.filterwarnings("ignore", module="nasim")
    from nasim.scenarios import generate_scenario, make_benchmark_scenario
    from nasim.scenarios.benchmark import AVAIL_GEN_BENCHMARKS
    return generate_scenario, make_benchmark_scenario, AVAIL_GEN_BENCHMARKS


def _addr(a):
    return f"({int(a[0])}, {int(a[1])})"


def _on(flags):
    """Names whose flag is True, in NASim's order."""
    return [str(k) for k, v in flags.items() if v]


def _os_value(v):
    return "None" if v is None else str(v)


def to_yaml(sc, header):
    d = sc.scenario_dict
    lines = [f"# {line}" for line in header] + ["#"]
    # In memory, subnets[0] is the Internet; the YAML lists only the real subnets.
    if len(d["subnets"]) != len(d["topology"]):
        raise SystemExit("unexpected subnets/topology sizes")
    lines.append(f"subnets: [{', '.join(str(int(n)) for n in d['subnets'][1:])}]")
    rows = [f"[{', '.join(str(int(x)) for x in row)}]" for row in d["topology"]]
    lines.append("topology: [" + (",\n           ".join(rows)) + "]")
    lines.append("sensitive_hosts:")
    for a, v in sorted(d["sensitive_hosts"].items()):
        lines.append(f"  {_addr(a)}: {float(v):g}")
    for key in ("os", "services", "processes"):
        lines.append(f"{key}:")
        lines += [f"  - {x}" for x in d[key]]
    for key, field in (("exploits", "service"), ("privilege_escalation", "process")):
        lines.append(f"{key}:")
        for name, e in d[key].items():
            lines += [f"  {name}:", f"    {field}: {e[field]}", f"    os: {_os_value(e['os'])}",
                      f"    prob: {float(e['prob']):g}", f"    cost: {float(e['cost']):g}",
                      f"    access: {ACCESS[int(e['access'])]}"]
    for key in ("service_scan_cost", "os_scan_cost", "subnet_scan_cost", "process_scan_cost"):
        lines.append(f"{key}: {float(d[key]):g}")
    lines.append("host_configurations:")
    for a, h in sorted(d["host"].items()):
        if h.firewall:
            raise SystemExit(f"host {a} has a per-host firewall, which nasim2aapef.py ignores")
        os_on = _on(h.os)
        if len(os_on) != 1:
            raise SystemExit(f"host {a}: expected exactly one OS, got {os_on}")
        lines += [f"  {_addr(a)}:", f"    os: {os_on[0]}",
                  f"    services: [{', '.join(_on(h.services))}]",
                  f"    processes: [{', '.join(_on(h.processes))}]"]
    lines.append("firewall:")
    for pair, allowed in sorted(d["firewall"].items()):
        lines.append(f"  {_addr(pair)}: [{', '.join(sorted(str(s) for s in allowed))}]")
    lines.append(f"step_limit: {int(d['step_limit'])}")
    return "\n".join(lines) + "\n"


def main(argv=None):
    # NASim's firewall generator draws from Python sets of service names, whose
    # order depends on string hashing: the same --seed gives a different
    # firewall in every process unless PYTHONHASHSEED is fixed. Re-run with 0.
    if os.environ.get("PYTHONHASHSEED") != "0":
        os.environ["PYTHONHASHSEED"] = "0"
        os.execv(sys.executable, [sys.executable, os.path.abspath(__file__)]
                 + (sys.argv[1:] if argv is None else list(argv)))
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--benchmark", help="NASim generated benchmark, e.g. medium-gen")
    ap.add_argument("--hosts", type=int)
    ap.add_argument("--services", type=int, default=5)
    ap.add_argument("--os", type=int, default=2)
    ap.add_argument("--processes", type=int, default=2)
    ap.add_argument("--restrictiveness", type=int, default=3)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("-o", "--output", required=True)
    args = ap.parse_args(argv)
    generate_scenario, make_benchmark_scenario, avail = _import_nasim()
    if args.benchmark:
        if args.benchmark not in avail:
            raise SystemExit(f"unknown benchmark {args.benchmark!r}; one of {sorted(avail)}")
        sc = make_benchmark_scenario(args.benchmark, seed=args.seed)
        params = {k: v for k, v in avail[args.benchmark].items() if k != "name"}
        what = f"NASim generated benchmark {args.benchmark}, seed {args.seed}"
    elif args.hosts:
        params = dict(num_hosts=args.hosts, num_services=args.services, num_os=args.os,
                      num_processes=args.processes, restrictiveness=args.restrictiveness)
        sc = generate_scenario(**params, seed=args.seed)
        what = f"NASim generate_scenario, seed {args.seed}"
    else:
        raise SystemExit("give --benchmark or --hosts")
    header = [what, "written by scripts/nasim_gen_export.py",
              "parameters: " + ", ".join(f"{k}={v}" for k, v in params.items()
                                         if k in ("num_hosts", "num_os", "num_services",
                                                  "num_processes", "num_exploits",
                                                  "restrictiveness", "exploit_probs"))]
    os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as fh:
        fh.write(to_yaml(sc, header))
    d = sc.scenario_dict
    print(f"wrote {args.output}: {len(d['host'])} hosts, {len(d['subnets'])} subnets, "
          f"{len(d['exploits'])} exploits, {len(d['privilege_escalation'])} privescs")


if __name__ == "__main__":
    main()
