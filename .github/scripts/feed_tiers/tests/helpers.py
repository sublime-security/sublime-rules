"""Builders for rule files and git repos used across the tests."""

from __future__ import annotations

import os
import subprocess
import uuid
from datetime import datetime, timezone
from pathlib import Path

_UNSET = object()


def rule_id(name: str) -> str:
    """A stable id per name, so tests can refer to a rule by name."""
    return str(uuid.uuid5(uuid.NAMESPACE_URL, name))


def rule_yaml(name: str, tier=_UNSET, rule_id_=_UNSET, source: str = "type.inbound", extra: str = "") -> bytes:
    """A rule file shaped like the real ones. tier=None or omitted writes no feed_tier key."""
    lines = [
        f'name: "{name}"',
        'description: "A test rule."',
        'type: "rule"',
        'severity: "medium"',
        "source: |",
        *[f"  {line}" for line in source.splitlines()],
        'attack_types:',
        '  - "Credential Phishing"',
    ]
    if extra:
        lines += extra.rstrip("\n").splitlines()
    if tier is not _UNSET and tier is not None:
        lines.append(f"feed_tier: {tier}")
    rid = rule_id(name) if rule_id_ is _UNSET else rule_id_
    if rid is not None:
        lines.append(f'id: "{rid}"')
    return ("\n".join(lines) + "\n").encode()


def rule_path(name: str) -> str:
    return f"detection-rules/{name}.yml"


def iso(when: datetime) -> str:
    return when.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S+00:00")


def run_git(repo: Path | str, *args: str, env: dict | None = None, input: bytes | None = None) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True, input=input, env={**os.environ, **(env or {})}
    )
    if result.returncode != 0:
        raise AssertionError(f"git {' '.join(args)} failed: {result.stderr.decode()}")
    return result.stdout.decode()


class Repo:
    """A working repo on main whose commits get chosen authors and dates."""

    def __init__(self, path: Path, name: str = "Test", email: str = "test@example.com"):
        self.path = Path(path)
        self.path.mkdir(parents=True, exist_ok=True)
        run_git(self.path, "init", "-q", "-b", "main")
        run_git(self.path, "config", "user.name", name)
        run_git(self.path, "config", "user.email", email)
        run_git(self.path, "config", "commit.gpgsign", "false")

    def commit(
        self,
        files: dict[str, bytes | str | None],
        message: str = "change",
        when: datetime | None = None,
        author: tuple[str, str] | None = None,
    ) -> str:
        """Writes the files (None deletes) and commits them all, even if nothing changed."""
        for path, content in files.items():
            target = self.path / path
            if content is None:
                if target.exists() or target.is_symlink():
                    target.unlink()
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content.encode() if isinstance(content, str) else content)
        run_git(self.path, "add", "-A")
        env = {}
        if when is not None:
            env["GIT_AUTHOR_DATE"] = env["GIT_COMMITTER_DATE"] = iso(when)
        if author is not None:
            env["GIT_AUTHOR_NAME"], env["GIT_AUTHOR_EMAIL"] = author
        run_git(self.path, "commit", "-q", "--allow-empty", "-m", message, env=env)
        return self.head()

    def rename(self, old: str, new: str, when: datetime | None = None, content: bytes | None = None) -> str:
        (self.path / new).parent.mkdir(parents=True, exist_ok=True)
        run_git(self.path, "mv", old, new)
        if content is not None:
            (self.path / new).write_bytes(content)
        return self.commit({}, message=f"rename {old}", when=when)

    def head(self) -> str:
        return run_git(self.path, "rev-parse", "HEAD").strip()

    def read(self, path: str, rev: str = "HEAD") -> bytes:
        return subprocess.run(
            ["git", "-C", str(self.path), "show", f"{rev}:{path}"], capture_output=True, check=True
        ).stdout

    def files(self, prefix: str = "detection-rules", rev: str = "HEAD") -> dict[str, bytes]:
        names = run_git(self.path, "ls-tree", "-r", "--name-only", rev, "--", f"{prefix}/").split("\n")
        return {name: self.read(name, rev) for name in names if name}

    def log(self, rev: str = "HEAD", fmt: str = "%H") -> list[str]:
        return run_git(self.path, "log", f"--format={fmt}", rev).strip().split("\n")
