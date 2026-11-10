#!/usr/bin/env python3
"""Opens a PR promoting each core_with_delay rule to core once it's been on main for the delay.

    promote.py --repo . --github-repo owner/name [--delay-days 90] [--as-of 2027-01-31] [--dry-run true]

--repo is a full-history checkout of main. For each due rule:
- skip it if a PR from its branch, auto/promote-core/<rule id>, is already open;
- otherwise commit the one-line tier change on top of HEAD, force-push the branch, open the PR and start
  rule-validate on it.

A PR closed without merging is opened again on the next run. To keep a rule private, change it to enterprise_only
(in the promotion PR or any other).

One rule failing doesn't stop the others; the run exits 1 at the end if any failed.
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import ci  # noqa: E402
from gitdates import DateError, first_merged  # noqa: E402
from github import GhCli, GitHub, GitHubError  # noqa: E402
from gittree import Entry, GitError, commit_changes, git, read_tree, rev_parse  # noqa: E402
from rules import CORE, CORE_WITH_DELAY, RULES_DIR, Rule, RuleError, parse_rules, set_tier  # noqa: E402

BRANCH_PREFIX = "auto/promote-core/"
LABEL = "auto-promote"
# PRs opened with GITHUB_TOKEN trigger no workflows, so the PR's required checks are started by hand on its branch.
REQUIRED_CHECK_WORKFLOWS = ("rule-validate.yml", "tier-check.yml")
DEFAULT_DELAY_DAYS = 90


@dataclass
class Candidate:
    rule: Rule
    entry: Entry
    first_merged: datetime

    @property
    def branch(self) -> str:
        return BRANCH_PREFIX + branch_key(self.rule)


@dataclass
class Report:
    opened: list[tuple[Candidate, str]] = field(default_factory=list)
    already_open: list[tuple[Candidate, str]] = field(default_factory=list)
    would_open: list[Candidate] = field(default_factory=list)
    waiting: list[Candidate] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def branch_key(rule: Rule) -> str:
    if rule.id is not None:
        key = rule.id
    else:
        key = os.path.splitext(os.path.basename(rule.path))[0]
    return re.sub(r"[^A-Za-z0-9._-]+", "-", key).strip("-.") or "rule"


def candidates(repo: str, rev: str = "HEAD") -> tuple[list[Candidate], list[str]]:
    """Every core_with_delay rule at rev, with its merge date."""
    files = read_tree(repo, rev, RULES_DIR)
    rules, errors = parse_rules({path: entry.content for path, entry in files.items()})
    out = []
    for path, rule in sorted(rules.items()):
        if rule.tier != CORE_WITH_DELAY:
            continue
        try:
            out.append(Candidate(rule, files[path], first_merged(repo, path, rule.id, rev)))
        except (DateError, GitError) as e:
            errors.append(str(e))
    return out, errors


def promote(
    repo: str,
    github: GitHub,
    now: datetime,
    delay: timedelta = timedelta(days=DEFAULT_DELAY_DAYS),
    dry_run: bool = False,
    base: str = "main",
    remote: str = "origin",
) -> Report:
    report = Report()
    head = rev_parse(repo, "HEAD")
    found, report.errors = candidates(repo, head)

    for candidate in found:
        if now - candidate.first_merged < delay:
            report.waiting.append(candidate)
            continue
        try:
            existing = github.find_open_pr(candidate.branch)
            if existing:
                report.already_open.append((candidate, existing))
                continue
            if dry_run:
                report.would_open.append(candidate)
                continue
            url = _open_pr(repo, github, head, candidate, now, base, remote)
            report.opened.append((candidate, url))
        except (GitError, GitHubError, RuleError) as e:
            report.errors.append(f"{candidate.rule.path}: {e}")

    return report


def _open_pr(repo: str, github: GitHub, head: str, candidate: Candidate, now: datetime, base: str, remote: str) -> str:
    rule = candidate.rule
    promoted = Entry(candidate.entry.mode, set_tier(rule.path, candidate.entry.content, CORE))
    days = (now - candidate.first_merged).days
    title = f"Promote {rule.name or rule.path} to core"
    commit = commit_changes(
        repo,
        head,
        {rule.path: promoted},
        f"{title}\n\nIt first merged {candidate.first_merged.date().isoformat()}, {days} days ago.\n",
    )
    git(repo, "push", "--force", remote, f"{commit}:refs/heads/{candidate.branch}")
    url = github.create_pr(branch=candidate.branch, base=base, title=title, body=_body(candidate, days), label=LABEL)
    for workflow in REQUIRED_CHECK_WORKFLOWS:
        github.dispatch_workflow(workflow, candidate.branch)
    return url


def _body(candidate: Candidate, days: int) -> str:
    rule = candidate.rule
    return "\n".join(
        [
            f"`{rule.path}` has been `{CORE_WITH_DELAY}` since it first merged on "
            f"{candidate.first_merged.date().isoformat()}, {days} days ago. Merging this makes it `{CORE}`, and the "
            "next sync publishes it to the public repo.",
            "",
            f"To keep it private instead, change `feed_tier` to `enterprise_only` in this PR and merge it. "
            "Closing this PR without merging only postpones it: it's opened again on the next run.",
            "",
            f"Rule id: `{rule.id}`" if rule.id else "This rule has no id.",
        ]
    )


def parse_as_of(value: str) -> datetime:
    if not value:
        return datetime.now(timezone.utc)
    parsed = datetime.fromisoformat(value)
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _summary(report: Report, dry_run: bool) -> str:
    lines = []
    for candidate, url in report.opened:
        lines.append(f"- opened {url} for `{candidate.rule.path}`")
    for candidate in report.would_open:
        lines.append(f"- would open a PR for `{candidate.rule.path}`")
    for candidate, url in report.already_open:
        lines.append(f"- already open: {url} for `{candidate.rule.path}`")
    for candidate in report.waiting:
        lines.append(f"- waiting: `{candidate.rule.path}` (first merged {candidate.first_merged.date().isoformat()})")
    return "\n".join(lines) if lines else "No core_with_delay rules."


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--repo", required=True, help="full-history checkout of main")
    parser.add_argument("--github-repo", required=True, help="owner/name")
    parser.add_argument("--delay-days", type=int, default=DEFAULT_DELAY_DAYS)
    parser.add_argument("--as-of", type=parse_as_of, default="", help="pretend it's this time (ISO 8601); default now")
    parser.add_argument("--dry-run", type=ci.bool_arg, default=False, metavar="true|false")
    args = parser.parse_args(argv)

    try:
        report = promote(
            args.repo, GhCli(args.github_repo), args.as_of, timedelta(days=args.delay_days), dry_run=args.dry_run
        )
    except GitError as e:
        ci.error(str(e))
        return 1

    message = _summary(report, args.dry_run)
    print(message)
    ci.summary(message)
    for problem in report.errors:
        ci.error(problem)
    return 1 if report.errors else 0


if __name__ == "__main__":
    sys.exit(main())
