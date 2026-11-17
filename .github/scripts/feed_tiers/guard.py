#!/usr/bin/env python3
"""Leak guard: fails if any rule in a tree's managed folders isn't public.

It's an independent re-check of what sync.py produced, run before the push. It parses every rule from scratch, so a
bug in the projection can't also hide the leak. YARA files are parsed twice, by plyara (as everything else here does)
and by libyara (yara-python, the real YARA compiler): both must find the same rules, each with
`feed_tier = "core"` in its meta, so a parser bug would have to be in both to let a rule through.

    guard.py --repo public --rev HEAD
"""

from __future__ import annotations

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import ci  # noqa: E402
from gittree import Entry, GitError, read_tree  # noqa: E402
from rules import CORE, MANAGED_DIRS, TIER_KEY, RuleError, is_yara, parse_file  # noqa: E402


def check(files: dict[str, Entry]) -> list[str]:
    problems = []
    for path in sorted(files):
        try:
            rules = parse_file(path, files[path].content)
        except RuleError as e:
            problems.append(str(e))
            continue
        for rule in rules:
            if not rule.is_public:
                problems.append(f"{rule.label if rule.yara_name else path}: is {rule.tier_label} and must not be public")
        if is_yara(path):
            problems += _check_yara(path, files[path].content, {rule.yara_name for rule in rules})
    return problems


def _check_yara(path: str, content: bytes, plyara_names: set[str]) -> list[str]:
    import yara  # only the guard needs it

    try:
        compiled = yara.compile(source=content.decode("utf-8"), includes=False)
    except (yara.Error, UnicodeDecodeError) as e:
        return [f"{path}: libyara can't compile it: {e}"]
    problems = []
    names = set()
    for rule in compiled:
        names.add(rule.identifier)
        tier = rule.meta.get(TIER_KEY)
        if tier != CORE:
            problems.append(f"{path}: libyara reads YARA rule {rule.identifier} as {TIER_KEY} {tier!r}, so it must not be public")
    if names != plyara_names:
        problems.append(
            f"{path}: libyara and plyara disagree about which rules it has ({', '.join(sorted(names ^ plyara_names))})"
        )
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--repo", required=True)
    parser.add_argument("--rev", default="HEAD")
    args = parser.parse_args(argv)

    try:
        files = read_tree(args.repo, args.rev, MANAGED_DIRS)
    except GitError as e:
        ci.error(str(e))
        return 1

    problems = check(files)
    for problem in problems:
        ci.error(problem)
    if problems:
        return 1
    print(f"Leak guard: every rule in the {len(files)} files under {', '.join(d + '/' for d in MANAGED_DIRS)} is public.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
