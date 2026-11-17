"""When a core_with_delay rule became core_with_delay, which starts its 90-day clock.

That's the most recent commit on main at which the rule went from not existing, or from another tier, to
core_with_delay (no feed_tier key counts as core_with_delay). Editing the rule doesn't move it, and neither does adding
the default line. Changing it to enterprise_only and back starts it again.

main is squash-merged, so a commit's committer date is when its PR merged. History is followed along the first
parent, so a PR merged with a merge commit counts from the merge.

A rule is followed back through the commits that changed its file, reading its tier just before each one:
- a rule with an id is the rule with that id, and a YARA rule is the YARA rule with that name, so if it isn't in the
  file just before a commit (the commit added or moved it), it's looked for elsewhere in the managed folders, and
  followed there if it was already core_with_delay;
- a rule without an id (automations, exclusions) is its path, so moving it starts its clock again, which matches the
  platform: it identifies a file with no id by its path.

A version of the file that doesn't parse counts as not core_with_delay, so the clock starts after it.

`git log --follow` is deliberately not used: rule files all share one structure, so its similarity guess calls an
unrelated older rule a copy or rename of a new one, which would promote the new rule early.
"""

from __future__ import annotations

import re
from datetime import datetime

from gittree import GitError, git
from rules import CORE_WITH_DELAY, MANAGED_DIRS, YARA_DIR, Rule, RuleError, parse_file

_ABSENT = object()


class DateError(Exception):
    pass


def delayed_since(repo: str, rule: Rule, rev: str = "HEAD") -> datetime:
    """When rule, which is core_with_delay at rev, last became core_with_delay."""
    path, commit = rule.path, rev
    while True:
        log = git(repo, "log", "--first-parent", "--format=%H %cI", commit, "--", path).decode().split("\n")
        moved = False
        for line in filter(None, log):
            sha, date = line.split(" ", 1)
            before = _tier(repo, f"{sha}^", path, rule)
            if before == CORE_WITH_DELAY:
                continue
            if before is _ABSENT:
                elsewhere = _find_elsewhere(repo, f"{sha}^", rule, path)
                if elsewhere is not None:
                    path, commit, moved = elsewhere, f"{sha}^", True
                    break
            return datetime.fromisoformat(date)
        if not moved:
            raise DateError(f"{rule.label}: can't find the commit that made it {CORE_WITH_DELAY}")


def _tier(repo: str, rev: str, path: str, rule: Rule):
    """The rule's effective tier at rev in path; _ABSENT if it isn't there; None if the file doesn't parse."""
    try:
        content = git(repo, "show", f"{rev}:{path}")
    except GitError:
        return _ABSENT  # no such file, or rev is before the first commit
    try:
        rules = parse_file(path, content)
    except RuleError:
        return None
    for other in rules:
        if rule.yara_name is not None:
            same = other.yara_name == rule.yara_name
        elif rule.id is not None:
            same = other.id == rule.id
        else:
            same = True  # identified by its path
        if same:
            return other.effective_tier
    return _ABSENT


def _find_elsewhere(repo: str, rev: str, rule: Rule, path: str) -> str | None:
    """Another path where rule was core_with_delay at rev, if it was."""
    if rule.yara_name is not None:
        pattern = rf"^[[:space:]]*((private|global)[[:space:]]+)*rule[[:space:]]+{_ere_escape(rule.yara_name)}([^A-Za-z0-9_]|$)"
        folders = [f"{YARA_DIR}/"]
    elif rule.id is not None:
        quote = "[\"']?"
        pattern = f"^{quote}id{quote}[[:space:]]*:[[:space:]]*{quote}{_ere_escape(rule.id)}{quote}[[:space:]]*(#.*)?$"
        folders = [f"{d}/" for d in MANAGED_DIRS]
    else:
        return None
    try:
        listing = git(repo, "grep", "-l", "-E", pattern, rev, "--", *folders).decode()
    except GitError:
        return None  # no match (git grep exits 1), or rev is before the first commit
    for line in sorted(filter(None, listing.split("\n"))):
        other = line.split(":", 1)[1]
        if other != path and _tier(repo, rev, other, rule) == CORE_WITH_DELAY:
            return other
    return None


def _ere_escape(text: str) -> str:
    return re.sub(r"([\\.^$|?*+()\[\]{}])", r"\\\1", text)
