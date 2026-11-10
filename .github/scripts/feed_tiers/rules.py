"""Reading a detection rule's feed tier, and changing it.

A rule's tier is the top-level `feed_tier` key:

    core              public, synced to the public repo immediately
    core_with_delay   private until promote.py opens a PR changing it to core
    enterprise_only   private, permanently

A rule with no `feed_tier` key predates tiers and is treated as core.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

import yaml

RULES_DIR = "detection-rules"

TIER_KEY = "feed_tier"
CORE = "core"
CORE_WITH_DELAY = "core_with_delay"
ENTERPRISE_ONLY = "enterprise_only"
TIERS = (CORE, CORE_WITH_DELAY, ENTERPRISE_ONLY)

# A top-level feed_tier line. Rule files are block mappings at column 0, and block scalars (like `source: |`) are
# always indented, so a match can't be inside another value.
_TIER_LINE = re.compile(rb"^(?:feed_tier|\"feed_tier\"|'feed_tier')[ \t]*:.*?(\r?\n|$)", re.MULTILINE)


class RuleError(Exception):
    def __init__(self, path: str, message: str):
        super().__init__(f"{path}: {message}")
        self.path = path
        self.message = message


@dataclass(frozen=True)
class Rule:
    path: str
    id: str | None
    name: str | None
    tier: str | None  # None when the rule has no feed_tier key

    @property
    def is_public(self) -> bool:
        return self.tier is None or self.tier == CORE

    @property
    def label(self) -> str:
        return f"{self.name} ({self.path})" if self.name else self.path


class _UniqueKeyLoader(yaml.CSafeLoader if yaml.__with_libyaml__ else yaml.SafeLoader):
    """A safe loader that rejects duplicate keys, which PyYAML otherwise resolves silently to the last one."""


def _construct_unique_mapping(loader, node, deep=False):
    loader.flatten_mapping(node)
    seen = set()
    for key_node, _ in node.value:
        key = loader.construct_object(key_node, deep=True)
        try:
            duplicate = key in seen
        except TypeError:
            raise yaml.constructor.ConstructorError(None, None, "unhashable key", key_node.start_mark)
        if duplicate:
            raise yaml.constructor.ConstructorError(None, None, f"duplicate key {key!r}", key_node.start_mark)
        seen.add(key)
    return loader.construct_mapping(node, deep)


_UniqueKeyLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_unique_mapping)


def load_rule_document(path: str, content: bytes) -> dict:
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError:
        raise RuleError(path, "is not valid UTF-8")
    try:
        documents = [d for d in yaml.load_all(text, Loader=_UniqueKeyLoader) if d is not None]
    except yaml.YAMLError as e:
        raise RuleError(path, f"is not valid YAML: {e}")
    if len(documents) != 1 or not isinstance(documents[0], dict):
        raise RuleError(path, "must contain exactly one YAML mapping")
    return documents[0]


def parse_rule(path: str, content: bytes) -> Rule:
    """Parses a rule file, failing on anything that would make its tier ambiguous."""
    document = load_rule_document(path, content)

    tier_lines = len(_TIER_LINE.findall(content))
    if TIER_KEY in document:
        tier = document[TIER_KEY]
        if not isinstance(tier, str) or tier not in TIERS:
            raise RuleError(path, f"{TIER_KEY} must be one of {', '.join(TIERS)}, not {tier!r}")
        # Anchors, merge keys or flow style could set the tier without a plain line, which promote.py can't edit.
        if tier_lines != 1:
            raise RuleError(path, f"{TIER_KEY} must be written as one plain top-level line")
    else:
        tier = None
        if tier_lines:
            raise RuleError(path, f"has a {TIER_KEY} line that isn't a top-level key")

    rule_id = document.get("id")
    if rule_id is not None and (not isinstance(rule_id, str) or not rule_id.strip()):
        raise RuleError(path, f"id must be a non-empty string, not {rule_id!r}")
    name = document.get("name")

    return Rule(path=path, id=rule_id, name=name if isinstance(name, str) else None, tier=tier)


def set_tier(path: str, content: bytes, tier: str) -> bytes:
    """Rewrites only the feed_tier line, leaving every other byte as it was."""
    if tier not in TIERS:
        raise ValueError(f"unknown tier {tier!r}")
    before = load_rule_document(path, content)
    parse_rule(path, content)

    matches = list(_TIER_LINE.finditer(content))
    if len(matches) != 1:
        raise RuleError(path, f"has no {TIER_KEY} line to change")
    match = matches[0]
    updated = content[: match.start()] + f"{TIER_KEY}: {tier}".encode() + match.group(1) + content[match.end() :]

    after = load_rule_document(path, updated)
    expected = dict(before, **{TIER_KEY: tier})
    if after != expected:
        raise RuleError(path, f"changing {TIER_KEY} would change other keys")
    return updated


def parse_rules(files: dict[str, bytes]) -> tuple[dict[str, Rule], list[str]]:
    """Parses every file, collecting every problem rather than stopping at the first.

    Two files with the same id are an error: the feed keys rules by id, so one would silently replace the other.
    """
    rules: dict[str, Rule] = {}
    errors: list[str] = []
    for path in sorted(files):
        try:
            rules[path] = parse_rule(path, files[path])
        except RuleError as e:
            errors.append(str(e))

    paths_by_id: dict[str, list[str]] = {}
    for rule in rules.values():
        if rule.id is not None:
            paths_by_id.setdefault(rule.id, []).append(rule.path)
    for rule_id, paths in sorted(paths_by_id.items()):
        if len(paths) > 1:
            errors.append(f"id {rule_id} is used by more than one rule: {', '.join(paths)}")

    return rules, errors
