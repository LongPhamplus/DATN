"""AAPEF — Automated Attack Path Execution Framework (research prototype).

A simulation-only framework that models red-team planning as a deterministic
state-space search problem over JSON scenario data, and compares BFS, DFS,
Dijkstra and Greedy Best-First search. No real exploitation, OS commands, VMs,
or external tools are involved — everything operates on in-memory scenario data.

See AAPEF_Research_Plan.md for the full design (v0.4).
"""

__version__ = "0.1.0"
