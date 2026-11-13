import os

import pytest

import tier_check
from gittree import Entry
from helpers import Repo, rule_path, rule_yaml
from rules import CORE, CORE_WITH_DELAY, ENTERPRISE_ONLY


def entries(files):
    return {p: Entry("100644", c) for p, c in files.items()}


def check(base, head, enabled=True):
    return tier_check.check(entries(base), entries(head), enabled)


def rule(name, tier=CORE, **kw):
    return {rule_path(name): rule_yaml(name, tier=tier, **kw)}


# "nokey" has no feed_tier key, so it's core_with_delay.
BASE = {**rule("nokey", None), **rule("core"), **rule("delayed", CORE_WITH_DELAY), **rule("ent", ENTERPRISE_ONLY)}

GATE_MESSAGE = "is {}, which isn't allowed yet: set feed_tier: core (NON_CORE_TIERS_ENABLED is off)"


class TestNewRules:
    @pytest.mark.parametrize("tier", [CORE, CORE_WITH_DELAY, ENTERPRISE_ONLY, None])
    def test_any_tier_or_none(self, tier):
        assert check(BASE, {**BASE, **rule("new", tier)}) == []

    def test_without_tier_before_enabled(self):
        problems = check(BASE, {**BASE, **rule("new", None)}, enabled=False)
        assert problems == [(rule_path("new"), GATE_MESSAGE.format("core_with_delay (no feed_tier key)"))]

    def test_rename_of_core_rule(self):
        head = {k: v for k, v in BASE.items() if k != rule_path("core")}
        head["detection-rules/moved.yml"] = BASE[rule_path("core")]
        assert check(BASE, head) == []

    def test_editing_a_rule_with_no_key(self):
        assert check(BASE, {**BASE, **rule("nokey", None, source="changed")}) == []

    def test_new_rule_without_id(self):
        assert check(BASE, {**BASE, **rule("noid", None, rule_id_=None)}) == []
        assert check(BASE, {**BASE, **rule("noid", CORE, rule_id_=None)}) == []


class TestCanaryGate:
    @pytest.mark.parametrize("tier", [CORE_WITH_DELAY, ENTERPRISE_ONLY])
    def test_non_core_blocked(self, tier):
        problems = check(BASE, {**BASE, **rule("new", tier)}, enabled=False)
        assert problems == [(rule_path("new"), GATE_MESSAGE.format(tier))]

    def test_core_allowed(self):
        assert check(BASE, {**BASE, **rule("new", CORE)}, enabled=False) == []

    def test_unchanged_files_are_not_rechecked(self):
        # nokey, delayed and ent are already on main; this PR didn't touch them.
        assert check(BASE, {**BASE, **rule("new", CORE)}, enabled=False) == []

    def test_stamping_pr_passes(self):
        # The one-time PR from stamp_core.py, before non-core tiers are enabled.
        base = {**rule("a", None), **rule("b", None)}
        assert check(base, {**rule("a", CORE), **rule("b", CORE)}, enabled=False) == []


class TestDemotion:
    @pytest.mark.parametrize("to", [CORE_WITH_DELAY, ENTERPRISE_ONLY, None])
    def test_in_place(self, to):  # S11
        problems = check(BASE, {**BASE, **rule("core", to)})
        assert len(problems) == 1 and "never demoted" in problems[0][1]

    def test_removing_the_core_line_says_why(self):
        problems = check(BASE, {**BASE, **rule("core", None)})
        assert "can't become core_with_delay (no feed_tier key)" in problems[0][1]

    @pytest.mark.parametrize("to", [CORE_WITH_DELAY, ENTERPRISE_ONLY, None])
    def test_with_rename(self, to):  # S12
        head = {k: v for k, v in BASE.items() if k != rule_path("core")}
        head["detection-rules/sneaky.yml"] = rule_yaml("core", tier=to)
        problems = check(BASE, head)
        assert [p for p, _ in problems] == ["detection-rules/sneaky.yml"]

    def test_with_new_id_same_path(self):
        problems = check(BASE, {**BASE, **rule("core", ENTERPRISE_ONLY, rule_id_="brand-new")})
        assert len(problems) == 1

    def test_blocked_even_before_enabled(self):
        problems = check(BASE, {**BASE, **rule("core", ENTERPRISE_ONLY)}, enabled=False)
        assert any("never demoted" in p for _, p in problems)

    def test_delete_is_fine(self):
        head = {k: v for k, v in BASE.items() if k != rule_path("core")}
        assert check(BASE, head) == []

    def test_promotion_is_fine(self):  # S7, S8
        assert check(BASE, {**BASE, **rule("delayed"), **rule("ent"), **rule("nokey")}) == []

    def test_moving_between_private_tiers_is_fine(self):
        head = {**BASE, **rule("delayed", None), **rule("ent", CORE_WITH_DELAY), **rule("nokey", ENTERPRISE_ONLY)}
        assert check(BASE, head) == []


class TestValidity:
    def test_unknown_tier(self):
        problems = check(BASE, {**BASE, **rule("new", "Core")})
        assert len(problems) == 1 and "must be one of" in problems[0][1]

    def test_unparseable(self):
        assert len(check(BASE, {**BASE, "detection-rules/x.yml": b"[\n"})) == 1

    def test_broken_unchanged_file_is_not_this_prs_problem(self):
        base = {**BASE, "detection-rules/broken.yml": b"[\n"}
        assert check(base, {**base, **rule("new", CORE)}) == []

    def test_duplicate_id(self):
        problems = check(BASE, {**BASE, "detection-rules/copy.yml": rule_yaml("copy", tier=CORE, rule_id_=rule_yaml("core").split(b'id: "')[1][:36].decode())})
        assert len(problems) == 1 and "also used by detection-rules/core.yml" in problems[0][1]


class TestCli:
    def test_against_git(self, tmp_path, monkeypatch, capsys):
        repo = Repo(tmp_path / "r")
        base = repo.commit(BASE)
        repo.commit(rule("core", ENTERPRISE_ONLY))
        monkeypatch.setenv("GITHUB_ACTIONS", "true")
        assert tier_check.main(["--repo", str(repo.path), "--base", base, "--head", "HEAD", "--non-core-tiers-enabled", "true"]) == 1
        assert f"::error file={rule_path('core')}::" in capsys.readouterr().err
        assert tier_check.main(["--repo", str(repo.path), "--base", "HEAD", "--head", "HEAD"]) == 0

    def test_symlink_fails(self, tmp_path):
        repo = Repo(tmp_path / "r")
        base = repo.commit(BASE)
        os.symlink("core.yml", repo.path / "detection-rules/link.yml")
        repo.commit({})
        assert tier_check.main(["--repo", str(repo.path), "--base", base]) == 1
