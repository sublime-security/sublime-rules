"""When a rule first merged into main, which starts its 90-day clock.

main is squash-merged, so a commit's committer date is when its PR merged.

- A rule with an id: the oldest commit that added or removed a top-level `id: <id>` line anywhere under
  detection-rules/. That's when a rule with this id first existed, so renames and moves keep the clock, and the
  same id is the same rule to the feed anyway. Mentions of the id elsewhere (comments, other keys, text inside
  `source`) don't match.
- A rule without an id: the oldest commit that added this exact path. Renaming it restarts the clock.

`git log --follow` is deliberately not used: rule files all share one structure, so its similarity guess calls an
unrelated older rule a copy or rename of a new one, which would promote the new rule early.
"""

from __future__ import annotations

import re
from datetime import datetime

from gittree import git
from rules import RULES_DIR


class DateError(Exception):
    pass


def first_merged(repo: str, path: str, rule_id: str | None, rev: str = "HEAD") -> datetime:
    if rule_id is None:
        log = git(repo, "log", "--diff-filter=A", "--format=%cI", rev, "--", path)
        what = f"{path}: can't find the commit that added it"
    else:
        quote = "[\"']?"
        pattern = f"^id:[[:space:]]*{quote}{_ere_escape(rule_id)}{quote}[[:space:]]*(#.*)?$"
        log = git(repo, "log", f"-G{pattern}", "--format=%cI", rev, "--", f"{RULES_DIR}/")
        what = f"{path}: can't find the commit that added id {rule_id}"

    dates = log.decode().split()
    if not dates:
        raise DateError(what)
    return datetime.fromisoformat(dates[-1])


def _ere_escape(text: str) -> str:
    return re.sub(r"([\\.^$|?*+()\[\]{}])", r"\\\1", text)
