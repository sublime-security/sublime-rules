"""The projection: what the public repo's rules should be, given the private repo's.

    public rules = every private rule whose tier is core or absent, byte for byte

This is a pure function of the two trees. It never looks at history, so running it again changes nothing, a missed
run is fixed by the next one, and anything pushed to the public repo by other means is undone.

It fails as a whole, rather than skipping a file, when:
- any private rule can't be parsed or has an unknown tier, so its tier is unknown;
- two private rules share an id;
- a rule that's public now would be removed while the private repo still has it under a non-public tier. Rules are
  never demoted (tier-check blocks it), so this only happens if a demotion slipped through.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from gittree import Entry
from rules import RuleError, parse_rule, parse_rules


class ProjectionError(Exception):
    def __init__(self, errors: list[str]):
        super().__init__("\n".join(errors))
        self.errors = errors


@dataclass
class Plan:
    desired: dict[str, Entry]
    added: list[str] = field(default_factory=list)
    updated: list[str] = field(default_factory=list)
    removed: list[str] = field(default_factory=list)

    @property
    def changed(self) -> bool:
        return bool(self.added or self.updated or self.removed)

    def changes(self) -> dict[str, Entry | None]:
        out: dict[str, Entry | None] = {path: self.desired[path] for path in self.added + self.updated}
        out.update({path: None for path in self.removed})
        return out


def project(private: dict[str, Entry], public: dict[str, Entry]) -> Plan:
    rules, errors = parse_rules({path: entry.content for path, entry in private.items()})
    if errors:
        raise ProjectionError(errors)

    desired = {path: private[path] for path, rule in rules.items() if rule.is_public}
    private_by_id = {rule.id: rule for rule in rules.values() if rule.id is not None}

    plan = Plan(desired=desired)
    for path in sorted(desired):
        if path not in public:
            plan.added.append(path)
        elif public[path] != desired[path]:
            plan.updated.append(path)

    for path in sorted(set(public) - set(desired)):
        held_back = _held_back_rule(path, public[path], rules, private_by_id)
        if held_back is not None:
            errors.append(
                f"{path} is public, but the private repo now has it as {held_back.tier} at {held_back.path}. "
                "Rules are never demoted: make it core again, or delete it from the private repo to remove it from both."
            )
        else:
            plan.removed.append(path)

    if errors:
        raise ProjectionError(errors)
    return plan


def _held_back_rule(path: str, public_entry: Entry, private_rules: dict, private_by_id: dict):
    """The private rule that keeps a public file from being removed, by path or by id, if there is one."""
    if path in private_rules and not private_rules[path].is_public:
        return private_rules[path]
    try:
        public_id = parse_rule(path, public_entry.content).id
    except RuleError:
        return None
    rule = private_by_id.get(public_id) if public_id is not None else None
    if rule is not None and not rule.is_public:
        return rule
    return None
