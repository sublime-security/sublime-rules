"""Small helpers for running under GitHub Actions: step outputs, the job summary and error annotations."""

from __future__ import annotations

import os
import sys


def set_output(name: str, value: str) -> None:
    path = os.environ.get("GITHUB_OUTPUT")
    if path:
        with open(path, "a") as f:
            f.write(f"{name}={value}\n")


def summary(markdown: str) -> None:
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if path:
        with open(path, "a") as f:
            f.write(markdown.rstrip() + "\n")


def error(message: str, path: str | None = None) -> None:
    """Prints an error, as an annotation when running under Actions."""
    if os.environ.get("GITHUB_ACTIONS") == "true":
        location = f" file={path}" if path else ""
        escaped = message.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
        print(f"::error{location}::{escaped}", file=sys.stderr)
    else:
        print(f"error: {message}", file=sys.stderr)


def bool_arg(value: str) -> bool:
    """Workflow inputs arrive as strings, and an unset input is empty."""
    if value in ("", "false"):
        return False
    if value == "true":
        return True
    raise ValueError(f"expected true or false, got {value!r}")
