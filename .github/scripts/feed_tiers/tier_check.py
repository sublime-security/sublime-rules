#!/usr/bin/env python3
"""The required PR check for feed tiers.

    tier_check.py --repo . --base <sha> --head <sha> [--non-core-tiers-enabled true]

Compares the rules at base and head:
- Every added or changed rule must parse, and any feed_tier must be a known value.
- No rule id may be used twice at head (the sync would fail on it).
- No demotion: a rule that's public at base (core, or no key) can't be core_with_delay or enterprise_only at head,
  matched by path and by id, so renaming it in the same PR doesn't hide the change. Deleting it is fine.
- Until non-core tiers are enabled (the repo variable NON_CORE_TIERS_ENABLED), only core is accepted. Once they
  are, a new rule must declare its tier: forgetting it would publish the rule.

A rule counts as new when neither its path nor its id exists at base.
"""

from __future__ import annotations

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import ci  # noqa: E402
from gittree import GitError, read_tree, rev_parse  # noqa: E402
from rules import CORE, RULES_DIR, TIER_KEY, TIERS, RuleError, parse_rule, parse_rules  # noqa: E402


def check(base_files: dict, head_files: dict, non_core_enabled: bool) -> list[tuple[str, str]]:
    """Returns (path, problem) pairs."""
    problems: list[tuple[str, str]] = []

    base_rules, _ = parse_rules({p: e.content for p, e in base_files.items()})
    base_public_paths = {p for p, r in base_rules.items() if r.is_public}
    base_public_ids = {r.id for r in base_rules.values() if r.is_public and r.id is not None}
    base_ids = {r.id for r in base_rules.values() if r.id is not None}

    changed = sorted(p for p, e in head_files.items() if base_files.get(p) != e)
    head_rules = {}
    for path in changed:
        try:
            head_rules[path] = parse_rule(path, head_files[path].content)
        except RuleError as e:
            problems.append((path, e.message))

    paths_by_id: dict[str, list[str]] = {}
    for path, entry in head_files.items():
        rule = head_rules.get(path)
        if rule is None and path not in changed:
            try:
                rule = parse_rule(path, entry.content)
            except RuleError:
                continue
        if rule is not None and rule.id is not None:
            paths_by_id.setdefault(rule.id, []).append(path)

    for path, rule in head_rules.items():
        if rule.id is not None and len(paths_by_id.get(rule.id, [])) > 1:
            others = ", ".join(p for p in sorted(paths_by_id[rule.id]) if p != path)
            problems.append((path, f"id {rule.id} is also used by {others}"))

        if rule.tier not in (None, CORE) and not non_core_enabled:
            problems.append((path, f"{TIER_KEY}: {rule.tier} isn't allowed yet; only {CORE} is (NON_CORE_TIERS_ENABLED is off)"))

        if not rule.is_public and (path in base_public_paths or rule.id in base_public_ids):
            problems.append(
                (
                    path,
                    f"this rule is public, so it can't become {rule.tier}. Rules are never demoted: to take it out "
                    "of the public feed, delete it.",
                )
            )

        is_new = path not in base_files and (rule.id is None or rule.id not in base_ids)
        if is_new and rule.tier is None and non_core_enabled:
            problems.append((path, f"new rules must set {TIER_KEY} to one of {', '.join(TIERS)}"))

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
        problems = check(read_tree(args.repo, base, RULES_DIR), read_tree(args.repo, head, RULES_DIR), args.non_core_tiers_enabled)
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
