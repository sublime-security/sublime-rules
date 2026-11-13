import os
import sys

import pytest

SCRIPTS_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, SCRIPTS_DIR)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


@pytest.fixture(autouse=True)
def isolated_git(monkeypatch, tmp_path_factory):
    """Keeps the developer's git config (signing, hooks, default branch) out of the tests."""
    home = tmp_path_factory.mktemp("home")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", os.devnull)
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    for name in ("GITHUB_ACTIONS", "GITHUB_OUTPUT", "GITHUB_STEP_SUMMARY", "GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GH_TOKEN", "GITHUB_TOKEN", "SIM_CREDENTIAL"):
        monkeypatch.delenv(name, raising=False)
