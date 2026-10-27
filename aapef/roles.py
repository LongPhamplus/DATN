"""Attack role of a CVE inferred from its CVSS v3 vector (MasterPlan §5.2).

A published, deterministic rule, so that assigning CVEs to hosts does not rest
on one person's judgement. It is an approximation: its agreement with a manual
classification is measured (KeHoachPhatTrien task 2.3) and reported.

Rule, first match wins:
    UI:R                    -> client-side    (needs a user to act, e.g. a
                                               malicious document: AV:L/UI:R)
    AV:L or AV:P            -> privesc        (needs local access first)
    PR:N (AV:N or AV:A)     -> initial-access
    PR:L or PR:H            -> lateral        (network service, needs an account)

The rule cannot produce `domain-takeover`; the hand-made catalog uses it for
CVE-2020-1472, which the rule calls initial-access.
"""

ROLES = ("initial-access", "lateral", "privesc", "client-side")


def role_from_vector(vec):
    """Role of a parsed vector dict (keys AV, AC, PR, UI[, S])."""
    if vec["UI"] == "R":
        return "client-side"
    if vec["AV"] in ("L", "P"):
        return "privesc"
    if vec["PR"] == "N":
        return "initial-access"
    return "lateral"
