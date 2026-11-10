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


def rule(name, tier=None, **kw):
    return {rule_path(name): rule_yaml(name, tier=tier, **kw)}


BASE = {**rule("legacy"), **rule("core", CORE), **rule("delayed", CORE_WITH_DELAY), **rule("ent", ENTERPRISE_ONLY)}


class TestNewRules:
    @pytest.mark.parametrize("tier", [CORE, CORE_WITH_DELAY, ENTERPRISE_ONLY])
    def test_with_tier(self, tier):
        assert check(BASE, {**BASE, **rule("new", tier)}) == []

    def test_without_tier_once_enabled(self):
        assert check(BASE, {**BASE, **rule("new")}) == [(rule_path("new"), "new rules must set feed_tier to one of core, core_with_delay, enterprise_only")]

    def test_without_tier_before_enabled(self):
        assert check(BASE, {**BASE, **rule("new")}, enabled=False) == []

    def test_rename_of_existing_legacy_rule_is_not_new(self):
        head = {k: v for k, v in BASE.items() if k != rule_path("legacy")}
        head["detection-rules/moved.yml"] = BASE[rule_path("legacy")]
        assert check(BASE, head) == []

    def test_editing_legacy_rule_needs_no_tier(self):
        assert check(BASE, {**BASE, **rule("legacy", source="changed")}) == []

    def test_new_rule_without_id(self):
        assert len(check(BASE, {**BASE, **rule("noid", rule_id_=None)})) == 1
        assert check(BASE, {**BASE, **rule("noid", CORE, rule_id_=None)}) == []


class TestCanaryGate:
    @pytest.mark.parametrize("tier", [CORE_WITH_DELAY, ENTERPRISE_ONLY])
    def test_non_core_blocked(self, tier):
        problems = check(BASE, {**BASE, **rule("new", tier)}, enabled=False)
        assert problems == [(rule_path("new"), f"feed_tier: {tier} isn't allowed yet; only core is (NON_CORE_TIERS_ENABLED is off)")]

    def test_core_allowed(self):
        assert check(BASE, {**BASE, **rule("new", CORE)}, enabled=False) == []

    def test_unchanged_files_are_not_rechecked(self):
        # Already on main; this PR didn't touch them.
        assert check(BASE, {**BASE, **rule("new", CORE)}, enabled=False) == []


class TestDemotion:
    @pytest.mark.parametrize("name", ["legacy", "core"])
    @pytest.mark.parametrize("to", [CORE_WITH_DELAY, ENTERPRISE_ONLY])
    def test_in_place(self, name, to):  # S11
        problems = check(BASE, {**BASE, **rule(name, to)})
        assert len(problems) == 1 and "never demoted" in problems[0][1]

    @pytest.mark.parametrize("to", [CORE_WITH_DELAY, ENTERPRISE_ONLY])
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

    @pytest.mark.parametrize("to", [CORE, None])
    def test_promotion_is_fine(self, to):  # S7, S8
        assert check(BASE, {**BASE, **rule("delayed", to), **rule("ent", to)}) == []

    def test_moving_between_private_tiers_is_fine(self):
        assert check(BASE, {**BASE, **rule("delayed", ENTERPRISE_ONLY), **rule("ent", CORE_WITH_DELAY)}) == []

    def test_legacy_to_explicit_core_is_fine(self):
        assert check(BASE, {**BASE, **rule("legacy", CORE)}) == []


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
