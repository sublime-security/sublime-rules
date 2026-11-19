#!/usr/bin/env python3
"""The required PR check for feed tiers.

    tier_check.py --repo . --base <sha> --head <sha> [--non-core-tiers-enabled true]

Compares the rules at base and head:
- Every added or changed rule must parse, and any feed_tier must be a known value.
- No rule id, or YARA rule name, may be used twice at head (the sync would fail on it).
- No demotion: a rule that's core at base can't be core_with_delay or enterprise_only at head (removing its
  feed_tier line counts, since no key means core_with_delay), matched by path and by id, and a YARA rule by its name,
  so renaming or moving it in the same PR doesn't hide the change. Deleting it is fine.
- Until non-core tiers are enabled (the repo variable NON_CORE_TIERS_ENABLED), every rule in an added or changed
  file must say core.
"""

from __future__ import annotations

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import ci  # noqa: E402
from gittree import GitError, read_tree, rev_parse  # noqa: E402
from rules import CORE, MANAGED_DIRS, TIER_KEY, PublicRules, RuleError, duplicate_errors, parse_file, parse_rules  # noqa: E402


def check(base_files: dict, head_files: dict, non_core_enabled: bool) -> list[tuple[str, str]]:
    """Returns (path, problem) pairs."""
    problems: list[tuple[str, str]] = []

    base_rules, _ = parse_rules({p: e.content for p, e in base_files.items()})
    base_public = PublicRules.of(base_rules)

    changed = sorted(p for p, e in head_files.items() if base_files.get(p) != e)
    head_rules: dict[str, list] = {}
    for path in changed:
        try:
            head_rules[path] = parse_file(path, head_files[path].content)
        except RuleError as e:
            problems.append((path, e.message))

    # Duplicates involving a changed file. Unchanged files that don't parse were already reported when they changed.
    every_rule = []
    for path, entry in head_files.items():
        rules = head_rules.get(path)
        if rules is None and path not in changed:
            try:
                rules = parse_file(path, entry.content)
            except RuleError:
                continue
        every_rule += rules or []
    for duplicate in duplicate_errors(every_rule):
        involved = sorted(p for p in head_rules if p in duplicate)
        if involved:
            problems.append((involved[0], duplicate))

    for path, rules in head_rules.items():
        for rule in rules:
            what = f"YARA rule {rule.yara_name} " if rule.yara_name else ""
            if not rule.is_public and not non_core_enabled:
                fix = f'{TIER_KEY} = "{CORE}" in its meta' if rule.yara_name else f"{TIER_KEY}: {CORE}"
                problems.append((path, f"{what}is {rule.tier_label}, which isn't allowed yet: set {fix} (NON_CORE_TIERS_ENABLED is off)"))
            if rule.is_public:
                continue
            if base_public.includes(rule):
                problems.append(
                    (
                        path,
                        f"{what or 'this rule '}is public, so it can't become {rule.tier_label}. Rules are never demoted: "
                        "to take it out of the public feed, delete it.",
                    )
                )

    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--repo", required=True)
    parser.add_argument("--base", required=True)
    parser.add_argument("--head", default="HEAD")
    parser.add_argument("--non-core-tiers-enabled", type=ci.bool_arg, default=False, metavar="true|false")
    args = parser.parse_args(argv)

    try:
        base = rev_parse(args.repo, args.base)
        head = rev_parse(args.repo, args.head)
        problems = check(read_tree(args.repo, base, MANAGED_DIRS), read_tree(args.repo, head, MANAGED_DIRS), args.non_core_tiers_enabled)
    except GitError as e:
        ci.error(str(e))
        return 1

    for path, problem in problems:
        ci.error(f"{path}: {problem}", path=path)
    if problems:
        return 1
    print(f"Feed tiers OK ({base[:12]}..{head[:12]}).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
