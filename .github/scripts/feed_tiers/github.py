"""The few GitHub operations promote.py needs, through the gh CLI and the job's GITHUB_TOKEN."""

from __future__ import annotations

import json
import subprocess
from typing import Protocol


class GitHubError(Exception):
    pass


class GitHub(Protocol):
    def find_open_pr(self, branch: str) -> str | None: ...

    def create_pr(self, *, branch: str, base: str, title: str, body: str, label: str) -> str: ...

    def dispatch_workflow(self, workflow: str, ref: str) -> None: ...


class GhCli:
    def __init__(self, repo: str):
        self.repo = repo

    def _gh(self, *args: str, input: str | None = None) -> str:
        result = subprocess.run(["gh", *args, "--repo", self.repo], input=input, capture_output=True, text=True)
        if result.returncode != 0:
            raise GitHubError(f"gh {args[0]} {args[1]} failed: {result.stderr.strip()}")
        return result.stdout

    def find_open_pr(self, branch: str) -> str | None:
        prs = json.loads(self._gh("pr", "list", "--head", branch, "--state", "open", "--json", "url"))
        return prs[0]["url"] if prs else None

    def create_pr(self, *, branch: str, base: str, title: str, body: str, label: str) -> str:
        out = self._gh(
            "pr", "create", "--base", base, "--head", branch, "--title", title, "--body-file", "-", "--label", label,
            input=body,
        )
        return out.strip().splitlines()[-1]

    def dispatch_workflow(self, workflow: str, ref: str) -> None:
        self._gh("workflow", "run", workflow, "--ref", ref)
