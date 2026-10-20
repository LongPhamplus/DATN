"""State model and the single, shared transition logic.

This module is the one place that knows how a State looks and how actions
change it. Search, Simulation and Validation all reuse `applicable`, `apply`
and `state_key` from here — there is no second copy of the transition rules.

Design decisions (see plan §5, §7):
- A State is just two dynamic fields: `access` (host -> level) and `known`
  (set of discovered facts). Environment facts and topology are static and
  live in the Scenario, not in the State.
- `apply` is pure: it returns a NEW State and never mutates its input.
- Effects are monotonic: `set_access` only raises a level, `learn` only adds a
  fact. Nothing lowers access or removes a fact. A consequence worth noting is
  that the reachable state-space is therefore a DAG (no true cycles are
  possible); duplicate states can still be reached by different paths.
"""

from dataclasses import dataclass, field

# Ordered access levels. Comparisons use these ranks (plan §5.2).
LEVELS = {"none": 0, "user": 1, "admin": 2}


@dataclass
class State:
    """Dynamic part of the world the simulated attacker can change.

    Treated as immutable by convention: never mutate in place, always go
    through `apply`, which returns a fresh State.
    """

    access: dict  # host_id -> level string in LEVELS
    known: set    # set of fact strings the attacker has discovered


def state_key(state):
    """Canonical, hashable identity of a state (plan §5.3).

    Sorting makes the key independent of dict/set ordering, so two equivalent
    states always share one identity. Used directly in `visited` sets and as
    keys in Dijkstra's distance map.
    """
    return (tuple(sorted(state.access.items())), tuple(sorted(state.known)))


def level_ge(current, required):
    """True if `current` access level is at least `required`."""
    return LEVELS[current] >= LEVELS[required]


def check_precondition(state, scenario, pre):
    """Evaluate one precondition against (dynamic state + static scenario)."""
    t = pre["type"]
    if t == "access_at_least":
        return level_ge(state.access[pre["host"]], pre["level"])
    if t == "known":
        return pre["fact"] in state.known
    if t == "env_fact":
        return pre["fact"] in scenario.env_facts
    if t == "reachable":
        return (pre["from"], pre["to"]) in scenario.topology
    raise ValueError(f"Unknown precondition type: {t!r}")


def applicable(state, scenario, action):
    """True if every precondition of `action` holds in `state`."""
    return all(check_precondition(state, scenario, p) for p in action.preconditions)


def apply(state, action):
    """Return a NEW state with `action`'s effects applied. Pure; no mutation.

    `set_access` only raises a level (never downgrades); `learn` only adds a
    fact. Setting an already-held level or learning a known fact leaves the
    state unchanged (a no-op; see `successors`).
    """
    access = dict(state.access)
    known = set(state.known)
    for eff in action.effects:
        t = eff["type"]
        if t == "set_access":
            host, level = eff["host"], eff["level"]
            if LEVELS[level] > LEVELS[access[host]]:
                access[host] = level
            # else: lower-or-equal target -> no change (no downgrade)
        elif t == "learn":
            known.add(eff["fact"])
        else:
            raise ValueError(f"Unknown effect type: {t!r}")
    return State(access, known)


def successors(state, scenario):
    """Deterministic, side-effect-free successor generation (plan §7.2).

    Returns `[(action, next_state, cost), ...]` for every applicable action
    whose result actually changes the state. No-op actions (result equal to
    the input by `state_key`) are excluded, so self-loops never appear in the
    state-space graph. Actions are iterated in scenario order, so the output
    order is stable (which the algorithms rely on for deterministic tie-breaks).
    """
    out = []
    sk = state_key(state)
    for a in scenario.actions:
        if not applicable(state, scenario, a):
            continue
        nxt = apply(state, a)
        if state_key(nxt) == sk:
            continue  # no-op: does not change the state -> not an edge
        out.append((a, nxt, a.cost))
    return out


def is_goal(state, goal):
    """True if `state` satisfies the goal predicate (plan §6.2)."""
    if goal["type"] == "access_at_least":
        return level_ge(state.access[goal["host"]], goal["level"])
    raise ValueError(f"Unknown goal type: {goal['type']!r}")


def initial_state(scenario):
    """Build the initial State from the scenario (fresh, owned copies)."""
    return State(dict(scenario.initial_access), set(scenario.initial_known))
