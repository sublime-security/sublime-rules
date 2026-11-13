#!/usr/bin/env python3
"""Adds `feed_tier: core` to every rule in a checkout that has no feed_tier key.

    stamp_core.py --repo . [--dry-run true]

A rule with no key is core_with_delay, so before the sync is turned on, every rule that's public today has to say
core, or the first sync would treat them all as demotions and refuse to run. This is that one-time change. It
edits the working tree only; commit the result in a PR.

It changes nothing if any rule can't be parsed or stamped.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import ci  # noqa: E402
from rules import CORE, RULES_DIR, RuleError, parse_rules, set_tier  # noqa: E402


def stamp(repo: str | Path, dry_run: bool = False) -> list[str]:
    """Returns the paths (relative to repo) it stamped, or would stamp. Raises RuleError listing every problem."""
    root = Path(repo)
    files = {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in sorted((root / RULES_DIR).rglob("*"))
        if path.is_file() and not path.is_symlink()
    }
    rules, errors = parse_rules(files)
    updates = {}
    for path, rule in rules.items():
        if rule.tier is None:
            try:
                updates[path] = set_tier(path, files[path], CORE)
            except RuleError as e:
                errors.append(str(e))
    if errors:
        raise RuleError(RULES_DIR, "\n".join(errors))
    if not dry_run:
        for path, content in updates.items():
            (root / path).write_bytes(content)
    return sorted(updates)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--repo", required=True)
    parser.add_argument("--dry-run", type=ci.bool_arg, default=False, metavar="true|false")
    args = parser.parse_args(argv)
    try:
        stamped = stamp(args.repo, args.dry_run)
    except RuleError as e:
        for problem in e.message.splitlines():
            ci.error(problem)
        return 1
    print(f"{'Would stamp' if args.dry_run else 'Stamped'} {len(stamped)} rules with feed_tier: {CORE}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
