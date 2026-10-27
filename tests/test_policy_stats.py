"""Tests for the policy statistics (bootstrap, Wilcoxon, win rate)."""

import csv
import os

import pytest

from aapef.policy_stats import bootstrap_ci, main, per_network, wilcoxon

SCEN_DIR = os.path.join(os.path.dirname(__file__), os.pardir, "scenarios")


def test_wilcoxon_exact_small_cases():
    # all 5 differences positive: only 2 of 32 sign patterns are as extreme
    w, p, r, n = wilcoxon([1, 2, 3, 4, 5])
    assert (w, n, r) == (15, 5, 1.0) and p == pytest.approx(2 / 32)
    w, p, r, n = wilcoxon([-1, -2, -3, -4, -5, -6])
    assert w == 0 and r == -1.0 and p == pytest.approx(2 / 64)
    # zeros are dropped; symmetric data gives p = 1
    w, p, r, n = wilcoxon([0, 1, -1, 2, -2])
    assert n == 4 and r == 0.0 and p == pytest.approx(1.0)
    assert wilcoxon([0, 0]) == (0.0, 1.0, 0.0, 0)


def test_wilcoxon_exact_matches_brute_force_with_ties():
    import itertools
    from aapef.policy_stats import _ranks
    diffs = [0.5, -0.5, 1, -0.25, 2, 2, -3, 1, 4, -5, 0.5, 6]
    w, p, _, n = wilcoxon(diffs)
    ranks = _ranks([abs(x) for x in diffs])
    half = sum(ranks) / 2
    extreme = sum(abs(sum(r for r, s in zip(ranks, signs) if s) - half) >= abs(w - half) - 1e-9
                  for signs in itertools.product((0, 1), repeat=n))
    assert p == pytest.approx(extreme / 2 ** n)
    # the normal approximation is close away from the extreme tail
    assert wilcoxon(diffs, exact_max=0)[1] == pytest.approx(p, abs=0.03)


def test_bootstrap_ci_contains_mean_and_is_deterministic():
    vals = [0.1, 0.2, 0.4, 0.5, 0.9]
    lo, hi = bootstrap_ci(vals)
    assert lo <= sum(vals) / len(vals) <= hi
    assert bootstrap_ci(vals) == (lo, hi)
    assert bootstrap_ci([0.3]) == (0.3, 0.3)


def test_random_policy_is_averaged_per_network():
    rows = [{"scenario": "n1", "policy": "random", "policy_model": "", "eval_model": "cvss",
             "auc": str(a), "k_block": kb} for a, kb in ((0.2, "1"), (0.6, ""))]
    data = per_network(rows)
    auc, kbs = data[("cvss", "random")]["n1"]
    assert auc == pytest.approx(0.4) and kbs == [1, None]


def test_stats_on_runner_output(tmp_path):
    from aapef.experiment import main as run
    run([os.path.join(SCEN_DIR, n) for n in ("small.json", "small-linear.json")]
        + ["--models", "cvss", "--K", "3", "--seeds", "5", "--out", str(tmp_path / "run")])
    main([str(tmp_path / "run" / "summary.csv"), "--K", "3", "--out", str(tmp_path / "st")])
    with open(tmp_path / "st" / "policies.csv", encoding="utf-8") as fh:
        pol = {r["policy"]: r for r in csv.DictReader(fh)}
    assert set(pol) == {"by-probability(cvss)", "context-greedy(cvss)", "optimal", "random"}
    assert all(r["networks"] == "2" for r in pol.values())
    assert float(pol["optimal"]["mean_auc"]) <= float(pol["random"]["mean_auc"])
    with open(tmp_path / "st" / "pairs.csv", encoding="utf-8") as fh:
        pairs = list(csv.DictReader(fh))
    assert len(pairs) == 6   # C(4, 2)
