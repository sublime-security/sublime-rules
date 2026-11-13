"""Reading and writing rule files as git objects.

Everything goes through git objects rather than the working tree, so the bytes are exactly what's committed: no
line-ending or other checkout filters, and no stray files in a workspace.
"""

from __future__ import annotations

import os
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

REGULAR_FILE_MODES = ("100644", "100755")


class GitError(Exception):
    pass


@dataclass(frozen=True)
class Entry:
    mode: str
    content: bytes


def git(repo: Path | str, *args: str, input: bytes | None = None, env: dict | None = None) -> bytes:
    result = subprocess.run(
        ["git", "-C", str(repo), *args],
        input=input,
        capture_output=True,
        env={**os.environ, **env} if env else None,
    )
    if result.returncode != 0:
        raise GitError(f"git {' '.join(args)} failed: {result.stderr.decode(errors='replace').strip()}")
    return result.stdout


def rev_parse(repo: Path | str, rev: str) -> str:
    return git(repo, "rev-parse", "--verify", "--end-of-options", f"{rev}^{{commit}}").decode().strip()


def read_tree(repo: Path | str, rev: str, prefix: str) -> dict[str, Entry]:
    """Every file under prefix at rev. Symlinks and submodules are errors, because their content isn't a rule."""
    listing = git(repo, "ls-tree", "-r", "-z", "--full-tree", rev, "--", f"{prefix}/")
    entries: list[tuple[str, str, str]] = []
    for record in listing.split(b"\0"):
        if not record:
            continue
        meta, path = record.split(b"\t", 1)
        mode, kind, sha = meta.decode().split(" ")
        path = path.decode()
        if kind != "blob" or mode not in REGULAR_FILE_MODES:
            raise GitError(f"{path} is a {'submodule' if kind == 'commit' else 'symlink' if mode == '120000' else kind}, not a regular file")
        entries.append((path, mode, sha))

    contents = _read_blobs(repo, [sha for _, _, sha in entries])
    return {path: Entry(mode, contents[sha]) for path, mode, sha in entries}


def _read_blobs(repo: Path | str, shas: list[str]) -> dict[str, bytes]:
    if not shas:
        return {}
    unique = list(dict.fromkeys(shas))
    out = git(repo, "cat-file", "--batch", input="".join(f"{sha}\n" for sha in unique).encode())
    blobs: dict[str, bytes] = {}
    pos = 0
    for sha in unique:
        header_end = out.index(b"\n", pos)
        got_sha, kind, size = out[pos:header_end].decode().split(" ")
        if got_sha != sha or kind != "blob":
            raise GitError(f"unexpected object {got_sha} ({kind}) while reading {sha}")
        start = header_end + 1
        blobs[sha] = out[start : start + int(size)]
        pos = start + int(size) + 1
    return blobs


_ZERO_SHA = "0" * 40


def commit_changes(
    repo: Path | str,
    parent: str,
    changes: dict[str, Entry | None],
    message: str,
    env: dict | None = None,
) -> str:
    """Creates a commit on top of parent that writes each Entry and deletes each path mapped to None. Nothing else
    changes. Returns the new commit's sha; no ref is moved."""
    with tempfile.TemporaryDirectory() as tmp:
        index_env = {**(env or {}), "GIT_INDEX_FILE": os.path.join(tmp, "index")}
        git(repo, "read-tree", parent, env=index_env)

        written = sorted(path for path, entry in changes.items() if entry is not None)
        blob_files = []
        for i, path in enumerate(written):
            blob_file = os.path.join(tmp, f"blob-{i}")
            with open(blob_file, "wb") as f:
                f.write(changes[path].content)
            blob_files.append(blob_file)
        shas = git(repo, "hash-object", "-w", "--no-filters", "--stdin-paths", input="\n".join(blob_files).encode()).decode().split()
        if len(shas) != len(written):
            raise GitError(f"hashed {len(shas)} blobs for {len(written)} files")
        blob_shas = dict(zip(written, shas))

        index_info = []
        for path, entry in sorted(changes.items()):
            if entry is None:
                # Mode 0 removes the path from the index.
                index_info.append(f"0 {_ZERO_SHA}\t{path}")
            else:
                index_info.append(f"{entry.mode} {blob_shas[path]}\t{path}")
        if index_info:
            records = "".join(f"{record}\0" for record in index_info).encode()
            git(repo, "update-index", "-z", "--index-info", input=records, env=index_env)

        tree = git(repo, "write-tree", env=index_env).decode().strip()

    return git(repo, "commit-tree", tree, "-p", parent, "-F", "-", input=message.encode(), env=env).decode().strip()
