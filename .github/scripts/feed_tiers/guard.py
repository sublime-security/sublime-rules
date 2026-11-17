#!/usr/bin/env python3
"""Leak guard: fails if any file in a tree's managed folders isn't public.

It's an independent re-check of what sync.py produced, run before the push. It parses every rule from scratch, so a
bug in the projection can't also hide the leak.

    guard.py --repo public --rev HEAD
"""

from __future__ import annotations

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import ci  # noqa: E402
from gittree import Entry, GitError, read_tree  # noqa: E402
from rules import MANAGED_DIRS, RuleError, parse_rule  # noqa: E402


def check(files: dict[str, Entry]) -> list[str]:
    problems = []
    for path in sorted(files):
        try:
            rule = parse_rule(path, files[path].content)
        except RuleError as e:
            problems.append(str(e))
            continue
        if not rule.is_public:
            problems.append(f"{path}: is {rule.tier_label} and must not be public")
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
    print(f"Leak guard: all {len(files)} files under {', '.join(d + '/' for d in MANAGED_DIRS)} are public.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
