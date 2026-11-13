#!/usr/bin/env python3
"""Projects the private repo's rules onto a checkout of the public repo, as one commit.

    sync.py --private private --public public [--dry-run true]

Both arguments are checkouts. The private repo is read at HEAD, and the commit goes on top of the public repo's HEAD,
which then points at it. Pushing is left to the workflow, after the leak guard has checked the result.

Only detection-rules/ is managed. Everything else in the public repo is left alone. The commit's author and
committer come from the public checkout's git config.

The sync is all or nothing: if any rule can't be projected (see project.py), it changes nothing and exits 1.

If the public repo was already synced from a newer private commit (its HEAD's Source-Commit trailer descends from
private HEAD), it changes nothing, so a delayed run can't roll the public repo back.
"""

from __future__ import annotations

import argparse
import os
import sys
from dataclasses import dataclass

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import ci  # noqa: E402
from gittree import Entry, GitError, commit_changes, git, read_tree, rev_parse  # noqa: E402
from project import Plan, ProjectionError, project  # noqa: E402
from rules import RULES_DIR, RuleError, parse_rule  # noqa: E402

SOURCE_TRAILER = "Source-Commit"
MAX_LISTED = 100


class SyncError(Exception):
    pass


@dataclass
class Result:
    plan: Plan | None
    source: str
    commit: str | None = None  # the new public commit, when one was made
    stale: bool = False


def sync(private: str, public: str, dry_run: bool = False) -> Result:
    source = rev_parse(private, "HEAD")
    public_head = rev_parse(public, "HEAD")

    if _already_synced_newer(private, public, source):
        return Result(plan=None, source=source, stale=True)

    public_files = read_tree(public, public_head, RULES_DIR)
    plan = project(read_tree(private, source, RULES_DIR), public_files)
    if not plan.changed or dry_run:
        return Result(plan=plan, source=source)

    commit = commit_changes(public, public_head, plan.changes(), commit_message(plan, public_files, source))

    # Re-read what was committed rather than trusting commit_changes.
    if read_tree(public, commit, RULES_DIR) != plan.desired:
        raise SyncError(f"the commit {commit} doesn't match the projection; not updating the public checkout")

    git(public, "update-ref", "-m", "feed tier sync", "HEAD", commit, public_head)
    return Result(plan=plan, source=source, commit=commit)


def _already_synced_newer(private: str, public: str, source: str) -> bool:
    synced = source_commit(public, "HEAD")
    if synced is None or synced == source:
        return False
    try:
        git(private, "cat-file", "-e", f"{synced}^{{commit}}")
    except GitError:
        # Not in the private checkout's history (a shallow clone, or rewritten history): no way to tell, so sync.
        return False
    try:
        git(private, "merge-base", "--is-ancestor", source, synced)
    except GitError:
        return False
    return True


def source_commit(repo: str, rev: str) -> str | None:
    """The private commit a public commit was synced from, if it was made by sync."""
    value = git(repo, "log", "-1", f"--format=%(trailers:key={SOURCE_TRAILER},valueonly,separator=%x20)", rev)
    value = value.decode().strip()
    return value.split()[-1] if value else None


def commit_message(plan: Plan, public_files: dict[str, Entry], source: str) -> str:
    """Built only from rules that are public before or after this commit, so nothing private can appear in it."""
    lines = [_subject(plan, public_files), ""]
    for heading, paths, files in (
        ("Added", plan.added, plan.desired),
        ("Updated", plan.updated, plan.desired),
        ("Removed", plan.removed, public_files),
    ):
        if not paths:
            continue
        lines.append(f"{heading}:")
        lines += [f"- {_describe(path, files[path])}" for path in paths[:MAX_LISTED]]
        if len(paths) > MAX_LISTED:
            lines.append(f"- and {len(paths) - MAX_LISTED} more")
        lines.append("")
    lines.append(f"{SOURCE_TRAILER}: {source}")
    return "\n".join(lines) + "\n"


def _subject(plan: Plan, public_files: dict[str, Entry]) -> str:
    """One rule: `Add rule <id>`. Several of one kind: `Add 3 rules`. Mixed: `Sync 4 rules: 3 added, 1 removed`."""
    kinds = [
        (paths, verb, word, files)
        for paths, verb, word, files in (
            (plan.added, "Add", "added", plan.desired),
            (plan.updated, "Update", "updated", plan.desired),
            (plan.removed, "Remove", "removed", public_files),
        )
        if paths
    ]
    if len(kinds) == 1:
        paths, verb, _, files = kinds[0]
        if len(paths) == 1:
            return f"{verb} rule {_rule_key(paths[0], files[paths[0]])}"
        return f"{verb} {len(paths)} rules"
    total = sum(len(paths) for paths, *_ in kinds)
    return f"Sync {total} rules: {', '.join(f'{len(paths)} {word}' for paths, _, word, _ in kinds)}"


def _rule_key(path: str, entry: Entry) -> str:
    """The rule's id, or its path if it has none or can't be parsed."""
    try:
        return parse_rule(path, entry.content).id or path
    except RuleError:
        return path


def _describe(path: str, entry: Entry) -> str:
    try:
        return parse_rule(path, entry.content).label
    except RuleError:
        return path


def _summary(result: Result, dry_run: bool) -> str:
    if result.stale:
        return f"The public repo was already synced from a newer private commit than {result.source}; nothing to do."
    plan = result.plan
    if not plan.changed:
        return f"The public repo already matches {result.source}."
    verb = "Would sync" if dry_run else "Synced"
    lines = [f"{verb} {result.source}: {len(plan.added)} added, {len(plan.updated)} updated, {len(plan.removed)} removed.", ""]
    for heading, paths in (("Added", plan.added), ("Updated", plan.updated), ("Removed", plan.removed)):
        lines += [f"- {heading.lower()}: `{path}`" for path in paths]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--private", required=True, help="checkout of the private repo")
    parser.add_argument("--public", required=True, help="checkout of the public repo")
    parser.add_argument("--dry-run", type=ci.bool_arg, default=False, metavar="true|false")
    args = parser.parse_args(argv)

    try:
        result = sync(args.private, args.public, dry_run=args.dry_run)
    except ProjectionError as e:
        for problem in e.errors:
            ci.error(problem)
        ci.error("Nothing was synced: the sync only runs when every rule can be projected.")
        return 1
    except (GitError, SyncError) as e:
        ci.error(str(e))
        return 1

    message = _summary(result, args.dry_run)
    print(message)
    ci.summary(message)
    ci.set_output("changed", "true" if result.commit else "false")
    ci.set_output("commit", result.commit or "")
    return 0


if __name__ == "__main__":
    sys.exit(main())
