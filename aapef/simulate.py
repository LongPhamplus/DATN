"""Simulation and validation of a candidate path (plan §8).

Simulation replays a path from a fresh copy of the initial state; validation
checks each step is applicable and actually changes the state, then checks the
final state against the goal. Both reuse `applicable`/`apply`/`state_key` from
`state` — no separate transition logic lives here.
"""

from .state import applicable, apply, initial_state, is_goal, state_key


def simulate_and_validate(path, scenario):
    """Replay `path` (a list of action ids) and validate it (plan §8).

    Returns a dict:
        valid        -> True if every step was applicable and state-changing
        goal_reached -> True if the final state satisfies the goal
        final_state  -> the State reached (initial state if path is empty)
        reason       -> short explanation when invalid, else None

    A step that is not applicable, or that is a no-op (does not change the
    state by `state_key`), makes the whole path invalid (plan §7.2 rule 3).
    An empty path is valid and leaves the initial state unchanged.
    """
    state = initial_state(scenario)
    for action_id in path:
        try:
            action = scenario.action_by_id(action_id)
        except KeyError:
            return {"valid": False, "goal_reached": False, "final_state": state,
                    "reason": f"unknown action id {action_id!r}"}
        if not applicable(state, scenario, action):
            return {"valid": False, "goal_reached": False, "final_state": state,
                    "reason": f"action {action_id!r} not applicable"}
        nxt = apply(state, action)
        if state_key(nxt) == state_key(state):
            return {"valid": False, "goal_reached": False, "final_state": state,
                    "reason": f"action {action_id!r} is a no-op (no state change)"}
        state = nxt

    goal_reached = is_goal(state, scenario.goal)
    return {"valid": True, "goal_reached": goal_reached, "final_state": state,
            "reason": None}


def path_cost(path, scenario):
    """Total configured cost of a path (sum of action costs)."""
    return sum(scenario.action_by_id(aid).cost for aid in path)
