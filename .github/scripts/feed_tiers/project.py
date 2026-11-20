"""The projection: what the public repo's rules should be, given the private repo's.

    public files = every private file in the managed folders whose feed_tier is core, plus the always-public ones
                   (insights/, and yara/ files that aren't .yar), byte for byte; and for a YARA file whose rules
                   have different tiers, just its core rules (see rules.public_content)

A rule with no feed_tier key is core_with_delay (see rules.py), so it stays private.

This is a pure function of the two trees. It never looks at history, so running it again changes nothing, a missed
run is fixed by the next one, and anything pushed to the public repo by other means is undone.

It fails as a whole, rather than skipping a file, when:
- any private rule can't be parsed or has an unknown tier, so its tier is unknown;
- two private rules share an id, or two YARA rules share a name;
- a YARA file mixes tiers in a way that can't be published as just its core rules (see rules._yara_split);
- a rule that's public now would be removed while the private repo still has it under a non-public tier (matched by
  path and id, and for YARA rules by name). Rules are never demoted (tier-check blocks it), so this only happens if a
  demotion slipped through.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from gittree import Entry
from rules import RuleError, is_yara, parse_file, parse_rules, public_content


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

    desired = {}
    for path in rules:
        content = public_content(path, private[path].content)
        if content is not None:
            desired[path] = Entry(private[path].mode, content)
    all_rules = [rule for file_rules in rules.values() for rule in file_rules]
    private_by_id = {rule.id: rule for rule in all_rules if rule.id is not None}
    private_by_yara_name = {rule.yara_name: rule for rule in all_rules if rule.yara_name is not None}

    plan = Plan(desired=desired)
    for path in sorted(desired):
        if path not in public:
            plan.added.append(path)
        elif public[path] != desired[path]:
            plan.updated.append(path)

    for path in sorted(set(public) - set(desired)):
        if is_yara(path):
            continue  # checked rule by rule below
        held_back = _held_back_rule(path, public[path], rules, private_by_id)
        if held_back is not None:
            errors.append(_demotion(path, held_back))
        else:
            plan.removed.append(path)

    for path in sorted(public):
        if not is_yara(path):
            continue
        try:
            public_rules = parse_file(path, public[path].content)
        except RuleError:
            public_rules = []  # replaced or removed; nothing in it can be matched to a private rule
        for rule in public_rules:
            held_back = private_by_yara_name.get(rule.yara_name)
            if held_back is not None and not held_back.is_public:
                errors.append(_demotion(f"YARA rule {rule.yara_name} in {path}", held_back))
        if path not in desired:
            plan.removed.append(path)
    plan.removed.sort()

    if errors:
        raise ProjectionError(errors)
    return plan


def _demotion(what: str, held_back) -> str:
    return (
        f"{what} is public, but the private repo now has it as {held_back.tier_label} at {held_back.path}. "
        "Rules are never demoted: make it core again, or delete it from the private repo to remove it from both."
    )


def _held_back_rule(path: str, public_entry: Entry, private_rules: dict, private_by_id: dict):
    """The private rule that keeps a public file from being removed, by path or by id, if there is one."""
    if path in private_rules and not any(rule.is_public for rule in private_rules[path]):
        return private_rules[path][0]
    try:
        public_rules = parse_file(path, public_entry.content)
    except RuleError:
        return None
    for public_rule in public_rules:
        rule = private_by_id.get(public_rule.id) if public_rule.id is not None else None
        if rule is not None and not rule.is_public:
            return rule
    return None
