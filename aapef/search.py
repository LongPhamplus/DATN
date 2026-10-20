"""Search algorithms: BFS, DFS, Dijkstra, Greedy Best-First (plan §10).

Each algorithm has the same shape:

    algo(initial, succ_fn, goal_fn[, heuristic]) -> (path, metrics)

where `path` is a list of action ids (or None if no path exists) and `metrics`
is a dict with `nodes_expanded` and `edges_examined`. Runtime is measured by
the caller (benchmark), not inside the algorithms.

Shared conventions (plan §10, §12.3):
- The goal is checked when a state is popped, *before* it is expanded. So if
  the initial state already satisfies the goal, every algorithm returns the
  empty path with nodes_expanded == edges_examined == 0.
- Visited / settled membership uses the canonical `state_key`.
- `edges_examined` counts every successor produced during an expansion,
  including edges to already-visited states.
- Priority queues (Dijkstra, Greedy) use a strictly increasing insertion
  counter as a tie-breaker, so heap entries never compare State objects.
"""

import heapq
from collections import deque

from .state import LEVELS, state_key


def _metrics(nodes_expanded, edges_examined):
    return {"nodes_expanded": nodes_expanded, "edges_examined": edges_examined}


def bfs(initial, succ_fn, goal_fn):
    """Breadth-first search: minimum number of edges (plan §10)."""
    frontier = deque([(initial, [])])
    visited = {state_key(initial)}
    ne = ee = 0
    while frontier:
        state, path = frontier.popleft()
        if goal_fn(state):
            return path, _metrics(ne, ee)
        ne += 1
        for action, nxt, _cost in succ_fn(state):
            ee += 1
            k = state_key(nxt)
            if k not in visited:
                visited.add(k)
                frontier.append((nxt, path + [action.id]))
    return None, _metrics(ne, ee)


def dfs(initial, succ_fn, goal_fn):
    """Depth-first search with a LIFO stack (plan §10, §4.3).

    Successors are pushed in reverse order so that the action listed first in
    the scenario is popped (explored) first. Deterministic; not optimal.
    """
    stack = [(initial, [])]
    visited = set()
    ne = ee = 0
    while stack:
        state, path = stack.pop()
        k = state_key(state)
        if k in visited:
            continue
        visited.add(k)
        if goal_fn(state):
            return path, _metrics(ne, ee)
        ne += 1
        succ = succ_fn(state)
        for action, nxt, _cost in reversed(succ):
            ee += 1
            stack.append((nxt, path + [action.id]))
    return None, _metrics(ne, ee)


def dijkstra(initial, succ_fn, goal_fn):
    """Dijkstra: minimum total cost with non-negative edge costs (plan §10)."""
    counter = 0
    start_key = state_key(initial)
    dist = {start_key: 0}
    # heap entries: (g, counter, state, path) -- counter keeps State out of
    # comparisons when g ties.
    pq = [(0, counter, initial, [])]
    counter += 1
    settled = set()
    ne = ee = 0
    while pq:
        g, _, state, path = heapq.heappop(pq)
        k = state_key(state)
        if k in settled:
            continue  # stale duplicate entry; not counted as an expansion
        settled.add(k)
        if goal_fn(state):
            return path, _metrics(ne, ee)
        ne += 1
        for action, nxt, cost in succ_fn(state):
            ee += 1
            nk = state_key(nxt)
            ng = g + cost
            if nk not in dist or ng < dist[nk]:
                dist[nk] = ng
                heapq.heappush(pq, (ng, counter, nxt, path + [action.id]))
                counter += 1
    return None, _metrics(ne, ee)


def greedy(initial, succ_fn, goal_fn, heuristic):
    """Greedy Best-First: expand by heuristic only (plan §10). Not optimal."""
    counter = 0
    pq = [(heuristic(initial), counter, initial, [])]
    counter += 1
    visited = {state_key(initial)}
    ne = ee = 0
    while pq:
        _h, _, state, path = heapq.heappop(pq)
        if goal_fn(state):
            return path, _metrics(ne, ee)
        ne += 1
        for action, nxt, _cost in succ_fn(state):
            ee += 1
            k = state_key(nxt)
            if k not in visited:
                visited.add(k)
                heapq.heappush(pq, (heuristic(nxt), counter, nxt, path + [action.id]))
                counter += 1
    return None, _metrics(ne, ee)


def astar(initial, succ_fn, goal_fn, heuristic):
    """A*: expand by f = g + h (plan §10, optional).

    Optimal for total cost when `heuristic` is admissible and consistent (see
    `make_admissible_heuristic`). Stale queue entries are skipped without
    counting an expansion, as in Dijkstra.
    """
    counter = 0
    best_g = {state_key(initial): 0}
    pq = [(heuristic(initial), counter, 0, initial, [])]
    counter += 1
    closed = set()
    ne = ee = 0
    while pq:
        _f, _, g, state, path = heapq.heappop(pq)
        k = state_key(state)
        if k in closed:
            continue
        closed.add(k)
        if goal_fn(state):
            return path, _metrics(ne, ee)
        ne += 1
        for action, nxt, cost in succ_fn(state):
            ee += 1
            nk = state_key(nxt)
            ng = g + cost
            if nk not in best_g or ng < best_g[nk]:
                best_g[nk] = ng
                heapq.heappush(
                    pq, (ng + heuristic(nxt), counter, ng, nxt, path + [action.id]))
                counter += 1
    return None, _metrics(ne, ee)


def make_admissible_heuristic(scenario):
    """Admissible, consistent heuristic for A* (plan §10).

    h(s) = 0 if the goal holds, else the cheapest cost of any action that
    raises the goal host to at least the goal level. Every path to the goal
    must contain such an action (access only ever rises), so h never exceeds
    the true remaining cost. Consistency: an edge into a goal state is such an
    action, so its cost >= h of its source; other edges cost >= 0 and leave h
    unchanged. If no action can reach the goal, h = 0 (no path exists anyway).
    """
    goal = scenario.goal
    need = LEVELS[goal["level"]]
    raising = [a.cost for a in scenario.actions
               if any(e["type"] == "set_access" and e["host"] == goal["host"]
                      and LEVELS[e["level"]] >= need for e in a.effects)]
    cheapest = min(raising) if raising else 0

    def h(state):
        return 0 if LEVELS[state.access[goal["host"]]] >= need else cheapest
    return h


def make_heuristic(goal):
    """Heuristic for Greedy (plan §10): access levels still missing for goal.

    Simple and goal-directed; not required to be admissible.
    """
    def h(state):
        if goal["type"] == "access_at_least":
            return max(0, LEVELS[goal["level"]] - LEVELS[state.access[goal["host"]]])
        return 0
    return h


# Names used by the CLI and benchmark. A plain dict is enough — no registry.
ALGORITHMS = ("bfs", "dfs", "dijkstra", "greedy", "astar")


def run_algorithm(name, initial, succ_fn, goal_fn, heuristic, astar_heuristic=None):
    """Dispatch to one algorithm by name. Returns (path, metrics).

    `heuristic` drives Greedy; `astar_heuristic` (admissible) drives A*.
    """
    if name == "astar":
        if astar_heuristic is None:
            raise ValueError("astar needs an admissible astar_heuristic")
        return astar(initial, succ_fn, goal_fn, astar_heuristic)
    if name == "bfs":
        return bfs(initial, succ_fn, goal_fn)
    if name == "dfs":
        return dfs(initial, succ_fn, goal_fn)
    if name == "dijkstra":
        return dijkstra(initial, succ_fn, goal_fn)
    if name == "greedy":
        return greedy(initial, succ_fn, goal_fn, heuristic)
    raise ValueError(f"Unknown algorithm {name!r}; choose from {ALGORITHMS}")
