"""Reading a detection rule's feed tier, and changing it.

A rule's tier is the top-level `feed_tier` key:

    core              public, synced to the public repo immediately
    core_with_delay   private until promote.py opens a PR changing it to core
    enterprise_only   private, permanently

A rule with no `feed_tier` key is core_with_delay, so forgetting the key can't publish a rule early. Rules that
predate tiers get an explicit `feed_tier: core` from stamp_core.py before the sync is turned on.

Which files have tiers (the folders the platform's feeds read):

    detection-rules/, dlp-rules/, automations/, exclusions/   every file; YAML, tier as above
    yara/*.yar                                                 `feed_tier = "<tier>"` in each YARA rule's meta;
                                                               every YARA rule has its own tier
    insights/, and yara/ files that aren't .yar               no tier: always public

Everything else in the repo isn't managed by the sync at all.

A YARA file whose rules have different tiers is published with only its core rules (see public_content). That only
works if the core rules don't need anything left out, so such a file can't have include lines or global rules, and a
core rule can't use a rule that isn't core.
"""

from __future__ import annotations

import re
from collections.abc import Collection, Iterable
from dataclasses import dataclass

import plyara
import yaml

RULES_DIR = "detection-rules"
YARA_DIR = "yara"
YARA_SUFFIX = ".yar"
# Folders whose files have a tier.
TIERED_DIRS = ("automations", RULES_DIR, "dlp-rules", "exclusions", YARA_DIR)
# Folders mirrored as they are, with no tiers.
ALWAYS_PUBLIC_DIRS = ("insights",)
# Everything the sync reads and writes.
MANAGED_DIRS = tuple(sorted(TIERED_DIRS + ALWAYS_PUBLIC_DIRS))

TIER_KEY = "feed_tier"
CORE = "core"
CORE_WITH_DELAY = "core_with_delay"
ENTERPRISE_ONLY = "enterprise_only"
TIERS = (CORE, CORE_WITH_DELAY, ENTERPRISE_ONLY)

DEFAULT_TIER = CORE_WITH_DELAY  # the tier of a rule with no feed_tier key

# A top-level feed_tier line. Rule files are block mappings at column 0, and block scalars (like `source: |`) are
# always indented, so a match can't be inside another value.
_TIER_LINE = re.compile(rb"^(?:feed_tier|\"feed_tier\"|'feed_tier')[ \t]*:.*?(\r?\n|$)", re.MULTILINE)
# A top-level id line, which set_tier adds a missing feed_tier line above; failing that, a top-level source line.
_ID_LINE = re.compile(rb"^(?:id|\"id\"|'id')[ \t]*:", re.MULTILINE)
_SOURCE_LINE = re.compile(rb"^(?:source|\"source\"|'source')[ \t]*:", re.MULTILINE)


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
    always_public: bool = False  # a file with no tier (see ALWAYS_PUBLIC_DIRS)
    yara_name: str | None = None  # for a rule in a .yar file, the YARA rule's name (a file can have several)

    @property
    def effective_tier(self) -> str:
        if self.always_public:
            return CORE
        return self.tier if self.tier is not None else DEFAULT_TIER

    @property
    def tier_label(self) -> str:
        if self.always_public:
            return f"{CORE} (always public)"
        return self.tier if self.tier is not None else f"{DEFAULT_TIER} (no {TIER_KEY} key)"

    @property
    def is_public(self) -> bool:
        return self.effective_tier == CORE

    @property
    def label(self) -> str:
        if self.yara_name:
            return f"YARA rule {self.yara_name} ({self.path})"
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


def is_managed(path: str) -> bool:
    return path.split("/", 1)[0] in MANAGED_DIRS


def has_tier(path: str) -> bool:
    """Whether the file at path has a tier, rather than being always public."""
    top = path.split("/", 1)[0]
    if top == YARA_DIR:
        return path.endswith(YARA_SUFFIX)
    return top in TIERED_DIRS


def is_yara(path: str) -> bool:
    return path.split("/", 1)[0] == YARA_DIR and path.endswith(YARA_SUFFIX)


def parse_file(path: str, content: bytes) -> list[Rule]:
    """Parses a file into its rules (one, except in a YARA file), failing on anything that would make a tier
    ambiguous or keep the file from being published as its core rules."""
    if not has_tier(path):
        return [Rule(path=path, id=None, name=None, tier=None, always_public=True)]
    if is_yara(path):
        return _yara_split(path, content)[0]
    return [_parse_yaml(path, content)]


def parse_rule(path: str, content: bytes) -> Rule:
    """parse_file, for a file that has one rule (anything but a YARA file with several)."""
    rules = parse_file(path, content)
    if len(rules) != 1:
        raise RuleError(path, f"has {len(rules)} YARA rules, not one")
    return rules[0]


def public_content(path: str, content: bytes) -> bytes | None:
    """What the public repo gets for this file: the file itself if every rule in it is core, nothing if none is, and
    for a YARA file with some core rules, just those rules (see _yara_split)."""
    if is_yara(path):
        return _yara_split(path, content)[1]
    return content if parse_rule(path, content).is_public else None


def _parse_yaml(path: str, content: bytes) -> Rule:
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


def _yara_rules(path: str, content: bytes) -> list[dict]:
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError:
        raise RuleError(path, "is not valid UTF-8")
    try:
        # plyara counts a CRLF as two lines; with LF its line numbers match _lines().
        rules = plyara.Plyara().parse_string(text.replace("\r\n", "\n"))
    except Exception as e:  # plyara raises several exception types for bad input
        raise RuleError(path, f"is not valid YARA: {e}")
    if not rules:
        raise RuleError(path, "has no YARA rules")
    return rules


def _yara_rule_tier(path: str, rule: dict) -> str | None:
    values = [value for entry in rule.get("metadata", []) for key, value in entry.items() if key == TIER_KEY]
    if not values:
        return None
    if len(values) > 1:
        raise RuleError(path, f"rule {rule['rule_name']} has more than one {TIER_KEY} in its meta")
    if not isinstance(values[0], str) or values[0] not in TIERS:
        raise RuleError(path, f"{TIER_KEY} must be one of {', '.join(TIERS)}, not {values[0]!r} (rule {rule['rule_name']})")
    return values[0]


_INCLUDE_LINE = re.compile(r"^[ \t]*include[ \t]", re.MULTILINE)
# A rule set in a condition, like `any of (abc*)`, which can use rules without naming them: a name ending in *
# inside an `of (...)` list. ($abc* in the same place is a string set, which is fine.)
_OF_LIST = re.compile(r"\bof\s*\(([^)]*)\)")
_RULE_SET = re.compile(r"(?<![$\w])[A-Za-z_]\w*\*")


def _yara_rule_start(name: str) -> re.Pattern:
    return re.compile(r"^[ \t]*(?:(?:private|global)[ \t]+)*rule[ \t]+" + re.escape(name) + r"(?![A-Za-z0-9_])")


_YARA_RULE_STOP = re.compile(r"\}[ \t]*(?://.*)?\r?\n?$")


def _yara_split(path: str, content: bytes) -> tuple[list[Rule], bytes | None]:
    """A YARA file's rules, each with the tier in its own meta, and the file's public content.

    The public content is the whole file if every rule is core, and None if none is. Otherwise it's the core rules'
    own lines, exactly as they are, after an `import` line for each module they use. Comments and anything else
    outside those rules is left out, since it could be about a rule that isn't public. That needs the core rules to
    stand on their own, so a file like that fails here if:
    - a core rule uses a rule that isn't core, or uses a rule set like `any of (abc*)`;
    - it has a global rule, which applies to every rule in the file;
    - it has an include line;
    - a rule doesn't start and end on lines of its own.
    """
    parsed = _yara_rules(path, content)
    rules: list[Rule] = []
    seen: set[str] = set()
    for rule in parsed:
        name = rule["rule_name"]
        if name in seen:
            raise RuleError(path, f"has more than one YARA rule named {name}")
        seen.add(name)
        rules.append(Rule(path=path, id=None, name=name, tier=_yara_rule_tier(path, rule), yara_name=name))

    public = [rule.is_public for rule in rules]
    if all(public):
        return rules, content
    if not any(public):
        return rules, None

    text = content.decode("utf-8")
    problems = []
    if _INCLUDE_LINE.search(text):
        problems.append("it has an include line")
    tiers = {rule.yara_name: rule for rule in rules}
    for rule in parsed:
        name = rule["rule_name"]
        if "global" in (rule.get("scopes") or []):
            problems.append(f"rule {name} is global, so it applies to every rule in the file")
        if not tiers[name].is_public:
            continue
        for dependency in sorted({term for term in rule.get("condition_terms", []) if term in tiers}):
            if not tiers[dependency].is_public:
                problems.append(f"core rule {name} uses rule {dependency}, which is {tiers[dependency].tier_label}")
        if any(_RULE_SET.search(group) for group in _OF_LIST.findall(rule.get("raw_condition", ""))):
            problems.append(f"core rule {name} uses a rule set (like `any of (abc*)`), which could include rules that aren't core")

    lines = _lines(text.replace("\r\n", "\n"))
    raw_lines = _lines(text)
    previous_stop = 0
    for rule in sorted(parsed, key=lambda r: r["start_line"]):
        start, stop = rule["start_line"] - 1, rule["stop_line"]
        if (
            start < previous_stop
            or not _yara_rule_start(rule["rule_name"]).match(lines[start])
            or not _YARA_RULE_STOP.search(lines[stop - 1])
        ):
            problems.append(f"rule {rule['rule_name']} doesn't start and end on lines of its own")
        previous_stop = stop
    if problems:
        raise RuleError(
            path,
            "has core and non-core rules, so only its core rules are published, but "
            + "; ".join(problems)
            + ". Fix that, or give every rule in the file the same tier.",
        )

    newline = _line_ending(raw_lines[0]) if raw_lines else "\n"
    imports = sorted({module for rule in parsed if tiers[rule["rule_name"]].is_public for module in rule.get("imports", [])})
    parts = ["".join(f'import "{module}"{newline}' for module in imports)] if imports else []
    for rule in parsed:
        if tiers[rule["rule_name"]].is_public:
            block = "".join(raw_lines[rule["start_line"] - 1 : rule["stop_line"]])
            parts.append(block if block.endswith("\n") else block + newline)
    return rules, newline.join(parts).encode("utf-8")


_META_HEADER = re.compile(r"^([ \t]*)meta[ \t]*:[ \t]*(?://.*)?$")
_SECTION_HEADER = re.compile(r"^([ \t]*)(?:strings|condition)[ \t]*:")
_META_ENTRY = re.compile(r"^([ \t]*)[A-Za-z_][A-Za-z0-9_]*[ \t]*=")
_META_TIER = re.compile(r'^([ \t]*feed_tier[ \t]*=[ \t]*)"[^"]*"')


def _lines(text: str) -> list[str]:
    """Lines with their endings, split only at newlines (str.splitlines also splits at form feeds and others)."""
    parts = text.split("\n")
    lines = [part + "\n" for part in parts[:-1]]
    return lines + [parts[-1]] if parts[-1] else lines


def _line_ending(line: str) -> str:
    return line[len(line.rstrip("\r\n")) :] or "\n"


def _set_tier_in_rule(path: str, rule: dict, lines: list[str], tier: str) -> list[str]:
    """lines are one rule's lines, with their endings. Sets feed_tier in its meta, adding a meta section if needed."""
    bare = [line.rstrip("\r\n") for line in lines]
    meta = next((i for i, line in enumerate(bare) if _META_HEADER.match(line)), None)
    value = f'{TIER_KEY} = "{tier}"'
    if meta is None:
        if rule.get("metadata"):
            raise RuleError(path, f"can't find the meta: line of rule {rule['rule_name']}")
        section = next((i for i, line in enumerate(bare) if _SECTION_HEADER.match(line)), None)
        if section is None:
            raise RuleError(path, f"can't find where to add meta to rule {rule['rule_name']}")
        indent = _SECTION_HEADER.match(bare[section]).group(1)
        newline = _line_ending(lines[section])
        added = [f"{indent}meta:{newline}", f"{indent * 2 or '    '}{value}{newline}"]
        return lines[:section] + added + lines[section:]

    end = next((i for i in range(meta + 1, len(bare)) if _SECTION_HEADER.match(bare[i])), len(bare) - 1)
    for i in range(meta + 1, end):
        match = _META_TIER.match(bare[i])
        if match:
            return lines[:i] + [match.group(1) + f'"{tier}"' + lines[i][match.end() :]] + lines[i + 1 :]
    entries = [i for i in range(meta + 1, end) if _META_ENTRY.match(bare[i])]
    after = entries[-1] if entries else meta
    if entries:
        indent = _META_ENTRY.match(bare[entries[-1]]).group(1)
    else:
        indent = _META_HEADER.match(bare[meta]).group(1) * 2 or "    "
    return lines[: after + 1] + [f"{indent}{value}{_line_ending(lines[after])}"] + lines[after + 1 :]


def _without_tier(rule: dict) -> tuple:
    metadata = [entry for entry in rule.get("metadata", []) if TIER_KEY not in entry]
    return (rule["rule_name"], rule.get("scopes"), rule.get("tags"), metadata, rule.get("raw_strings"), rule.get("raw_condition"))


def _set_yara_tier(path: str, content: bytes, tier: str, names: Collection[str] | None) -> bytes:
    rules = _yara_rules(path, content)
    if names is not None:
        missing = sorted(set(names) - {rule["rule_name"] for rule in rules})
        if missing:
            raise RuleError(path, f"has no YARA rule named {', '.join(missing)}")
    chosen = {rule["rule_name"] for rule in rules if names is None or rule["rule_name"] in names}
    lines = _lines(content.decode("utf-8"))
    # From the last rule up, so earlier rules' line numbers stay right.
    for rule in sorted(rules, key=lambda r: r["start_line"], reverse=True):
        if rule["rule_name"] not in chosen:
            continue
        start, stop = rule["start_line"] - 1, rule["stop_line"]
        lines[start:stop] = _set_tier_in_rule(path, rule, lines[start:stop], tier)
    updated = "".join(lines).encode("utf-8")

    after = _yara_rules(path, updated)
    expected_tiers = [tier if r["rule_name"] in chosen else _yara_rule_tier(path, r) for r in rules]
    if [_without_tier(r) for r in after] != [_without_tier(r) for r in rules] or [
        _yara_rule_tier(path, r) for r in after
    ] != expected_tiers:
        raise RuleError(path, f"changing {TIER_KEY} would change other parts of the file")
    return updated


def set_tier(path: str, content: bytes, tier: str, names: Collection[str] | None = None) -> bytes:
    """Rewrites only the feed_tier line, leaving every other byte as it was.

    A rule with no feed_tier line gets one above its top-level id line if it has exactly one, else above its top-level
    source line if it has exactly one (automations and exclusions have no id, and often end in a source block with no
    final newline, which a line after it would change), else at the end.

    In a YARA file, each rule named in names (every rule, if names is None) gets `feed_tier = "<tier>"`, replacing
    its value or added as its last meta entry (with a meta section if it has none). names is only for YARA files.
    """
    if tier not in TIERS:
        raise ValueError(f"unknown tier {tier!r}")
    if not has_tier(path):
        raise RuleError(path, "is always public and has no tier")
    if is_yara(path):
        return _set_yara_tier(path, content, tier, names)
    if names is not None:
        raise ValueError("names is only for YARA files")
    before = load_rule_document(path, content)
    rule = parse_rule(path, content)

    if rule.tier is not None:
        match = _TIER_LINE.search(content)
        updated = content[: match.start()] + f"{TIER_KEY}: {tier}".encode() + match.group(1) + content[match.end() :]
    else:
        newline = b"\r\n" if b"\r\n" in content else b"\n"
        line = f"{TIER_KEY}: {tier}".encode() + newline
        ids = list(_ID_LINE.finditer(content))
        sources = list(_SOURCE_LINE.finditer(content))
        anchor = ids[0] if len(ids) == 1 else sources[0] if len(sources) == 1 else None
        if anchor is not None:
            updated = content[: anchor.start()] + line + content[anchor.start() :]
        else:
            updated = content + (newline if content and not content.endswith(b"\n") else b"") + line

    after = load_rule_document(path, updated)
    expected = dict(before, **{TIER_KEY: tier})
    if after != expected:
        raise RuleError(path, f"changing {TIER_KEY} would change other keys")
    return updated


def parse_rules(files: dict[str, bytes]) -> tuple[dict[str, list[Rule]], list[str]]:
    """Parses every file into its rules, collecting every problem rather than stopping at the first.

    Two files with the same id are an error: the feed keys rules by id, so one would silently replace the other. So
    are two YARA rules with the same name, which is how a YARA rule is tracked (its tier history, its promotion).
    """
    rules: dict[str, list[Rule]] = {}
    errors: list[str] = []
    for path in sorted(files):
        try:
            rules[path] = parse_file(path, files[path])
        except RuleError as e:
            errors.append(str(e))
    errors += duplicate_errors(rule for file_rules in rules.values() for rule in file_rules)
    return rules, errors


def duplicate_errors(rules: Iterable[Rule]) -> list[str]:
    paths_by_id: dict[str, list[str]] = {}
    paths_by_yara_name: dict[str, list[str]] = {}
    for rule in rules:
        if rule.id is not None:
            paths_by_id.setdefault(rule.id, []).append(rule.path)
        if rule.yara_name is not None:
            paths_by_yara_name.setdefault(rule.yara_name, []).append(rule.path)
    errors = [
        f"id {rule_id} is used by more than one rule: {', '.join(sorted(paths))}"
        for rule_id, paths in sorted(paths_by_id.items())
        if len(paths) > 1
    ]
    errors += [
        f"YARA rule name {name} is used more than once: {', '.join(sorted(paths))}"
        for name, paths in sorted(paths_by_yara_name.items())
        if len(paths) > 1
    ]
    return errors


@dataclass(frozen=True)
class PublicRules:
    """The rules that are public (core) at some commit, keyed the way a demotion is detected."""

    paths: frozenset[str]  # non-YARA rules, by path
    ids: frozenset[str]  # non-YARA rules, by id
    yara_names: frozenset[str]  # YARA rules, by name

    @classmethod
    def of(cls, rules: dict[str, list[Rule]]) -> PublicRules:
        public = [r for file_rules in rules.values() for r in file_rules if r.is_public]
        return cls(
            paths=frozenset(r.path for r in public if r.yara_name is None),
            ids=frozenset(r.id for r in public if r.id is not None),
            yara_names=frozenset(r.yara_name for r in public if r.yara_name is not None),
        )

    def includes(self, rule: Rule) -> bool:
        """Whether rule was one of these: a YARA rule by its name, any other rule by its path or its id, so renaming
        or moving it doesn't hide it."""
        if rule.yara_name is not None:
            return rule.yara_name in self.yara_names
        return rule.path in self.paths or rule.id in self.ids
