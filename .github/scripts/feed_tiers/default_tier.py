#!/usr/bin/env python3
"""Adds `feed_tier: core_with_delay` to rules a PR adds or changes without a feed_tier key, and says so on the PR.

Every folder with tiers counts (see rules.TIERED_DIRS); a YARA file gets `// feed_tier: core_with_delay` as its first
line.

    default_tier.py --repo . --base <sha> --head <sha> --branch <pr branch> --github-repo owner/name --pr <number>

A rule with no key is already core_with_delay, so the added line never changes a rule's tier: it only makes the
default visible in the file and in review. --base is the PR's base branch; the PR's rules are those that differ
between the merge base and --head.

If any rule needs the line, one commit on top of --head adds it to each, and is pushed to the PR branch. A push made
with GITHUB_TOKEN starts no workflows, so the PR's required checks are then started by hand on the branch, the same
way promote.py does it. If the branch moved meanwhile, the push is rejected and nothing else happens: that newer push
started its own run, which will see the same rules.

Rules that don't parse, or where the line can't be added without changing anything else, are left alone: tier-check
reports parse errors, and the others are listed in the job summary (and in the comment, if one is posted). The bot
comments only when it pushes, so a PR gets one comment per commit it adds, not one per push.
"""

from __future__ import annotations

import argparse
import os
import sys
from dataclasses import dataclass, field

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import ci  # noqa: E402
from github import GhCli, GitHub, GitHubError  # noqa: E402
from gittree import Entry, GitError, commit_changes, git, read_tree, rev_parse  # noqa: E402
from promote import DEFAULT_DELAY_DAYS, REQUIRED_CHECK_WORKFLOWS  # noqa: E402
from rules import CORE, CORE_WITH_DELAY, ENTERPRISE_ONLY, MANAGED_DIRS, TIER_KEY, RuleError, parse_rule, set_tier  # noqa: E402

COMMIT_TITLE = f"Add the default {TIER_KEY}: {CORE_WITH_DELAY}"
# Marks the bot's comments, so they're easy to find.
COMMENT_MARKER = "<!-- feed-tier-default -->"


@dataclass
class Result:
    updates: dict[str, Entry] = field(default_factory=dict)  # path -> the rule with the line added
    skipped: list[tuple[str, str]] = field(default_factory=list)  # (path, why)


def missing_tiers(base_files: dict[str, Entry], head_files: dict[str, Entry]) -> Result:
    """The rules added or changed since base that have no feed_tier key, with the default line added."""
    result = Result()
    for path in sorted(head_files):
        entry = head_files[path]
        if base_files.get(path) == entry:
            continue
        try:
            rule = parse_rule(path, entry.content)
        except RuleError:
            continue  # tier-check reports it
        if rule.tier is not None or rule.always_public:
            continue
        try:
            result.updates[path] = Entry(entry.mode, set_tier(path, entry.content, CORE_WITH_DELAY))
        except RuleError as e:
            result.skipped.append((path, e.message))
    return result


def commit_message(paths: list[str]) -> str:
    listed = "\n".join(f"- {path}" for path in paths)
    return f"{COMMIT_TITLE}\n\nThese rules had no {TIER_KEY}, which means {CORE_WITH_DELAY}:\n\n{listed}\n"


def comment_body(paths: list[str], skipped: list[tuple[str, str]], commit: str) -> str:
    lines = [COMMENT_MARKER]
    if paths:
        lines += [
            f"**`{TIER_KEY}` was missing, so the default was applied.** Commit {commit} adds "
            f"`{TIER_KEY}: {CORE_WITH_DELAY}` to:",
            "",
            *[f"- `{path}`" for path in paths],
            "",
            f"A rule with no `{TIER_KEY}` was already `{CORE_WITH_DELAY}`, so this doesn't change anything; it just "
            f"makes the tier visible. `{CORE_WITH_DELAY}` keeps the rule out of the public repo until a promotion PR "
            f"makes it `{CORE}`, {DEFAULT_DELAY_DAYS} days after it first merges. To choose differently, change the "
            f"line to `{CORE}` (public as soon as this merges) or `{ENTERPRISE_ONLY}` (never public).",
            "",
            "Pull before you push to this branch again.",
        ]
    if skipped:
        if paths:
            lines.append("")
        lines += [
            f"These rules have no `{TIER_KEY}` and the line couldn't be added automatically, so they're "
            f"`{CORE_WITH_DELAY}`. Add `{TIER_KEY}:` yourself if you want it in the file:",
            "",
            *[f"- `{path}`: {why}" for path, why in skipped],
        ]
    return "\n".join(lines) + "\n"


def add_defaults(
    repo: str, github: GitHub, base: str, head: str, branch: str, pr: int, remote: str = "origin"
) -> tuple[Result, str | None]:
    """Returns what was found and the pushed commit (None if nothing was pushed)."""
    merge_base = git(repo, "merge-base", base, head).decode().strip()
    result = missing_tiers(read_tree(repo, merge_base, MANAGED_DIRS), read_tree(repo, head, MANAGED_DIRS))
    paths = sorted(result.updates)
    commit = None
    if paths:
        commit = commit_changes(repo, head, dict(result.updates), commit_message(paths))
        try:
            git(repo, "push", remote, f"{commit}:refs/heads/{branch}")
        except GitError as e:
            print(f"Didn't push, probably because {branch} moved since this run started; its own run takes over.\n{e}")
            return result, None
        for workflow in REQUIRED_CHECK_WORKFLOWS:
            github.dispatch_workflow(workflow, branch)
        github.comment_pr(pr, comment_body(paths, result.skipped, commit[:12]))
    return result, commit


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--repo", required=True, help="full-history checkout of the PR branch")
    parser.add_argument("--base", required=True, help="the PR's base branch")
    parser.add_argument("--head", default="HEAD")
    parser.add_argument("--branch", required=True, help="the PR's branch, which the commit is pushed to")
    parser.add_argument("--github-repo", required=True, help="owner/name")
    parser.add_argument("--pr", type=int, required=True)
    args = parser.parse_args(argv)

    try:
        result, commit = add_defaults(
            args.repo, GhCli(args.github_repo), rev_parse(args.repo, args.base), rev_parse(args.repo, args.head),
            args.branch, args.pr,
        )
    except (GitError, GitHubError, RuleError) as e:
        ci.error(str(e))
        return 1

    if commit:
        message = f"Added {TIER_KEY}: {CORE_WITH_DELAY} to {len(result.updates)} rule(s) in {commit[:12]}."
    elif result.updates:
        message = "Rules need the default line, but the branch moved; the newer run handles them."
    else:
        message = f"Every added or changed rule has a {TIER_KEY}."
    for path, why in result.skipped:
        message += f"\n- couldn't add {TIER_KEY} to `{path}`: {why}"
    print(message)
    ci.summary(message)
    return 0


if __name__ == "__main__":
    sys.exit(main())
