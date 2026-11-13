"""stamp_core.py: the one-time change giving every rule with no feed_tier key an explicit core."""

import pytest

import stamp_core
import tier_check
from gittree import read_tree
from helpers import Repo, rule_path, rule_yaml
from project import ProjectionError, project
from rules import CORE, ENTERPRISE_ONLY, RULES_DIR, parse_rule


def disk(repo, path):
    return (repo.path / path).read_bytes()


@pytest.fixture
def repo(tmp_path):
    r = Repo(tmp_path / "r")
    r.commit(
        {
            rule_path("a"): rule_yaml("a", tier=None),
            rule_path("b"): rule_yaml("b", tier=None).replace(b"\n", b"\r\n"),
            "detection-rules/noid": rule_yaml("noid", tier=None, rule_id_=None),
            rule_path("core"): rule_yaml("core", tier=CORE),
            rule_path("ent"): rule_yaml("ent", tier=ENTERPRISE_ONLY),
            "yara/x.yml": "not: a rule\n",
        }
    )
    return r


def test_stamps_only_rules_with_no_key(repo):
    before = {p: disk(repo, p) for p in (rule_path("core"), rule_path("ent"), "yara/x.yml")}
    assert stamp_core.stamp(repo.path) == sorted([rule_path("a"), rule_path("b"), "detection-rules/noid"])
    assert disk(repo, rule_path("a")) == rule_yaml("a", tier=CORE)
    assert disk(repo, rule_path("b")) == rule_yaml("b", tier=CORE).replace(b"\n", b"\r\n")
    assert disk(repo, "detection-rules/noid") == rule_yaml("noid", tier=None, rule_id_=None) + b"feed_tier: core\n"
    assert {p: disk(repo, p) for p in before} == before


def test_dry_run_writes_nothing(repo):
    assert len(stamp_core.stamp(repo.path, dry_run=True)) == 3
    assert disk(repo, rule_path("a")) == rule_yaml("a", tier=None)


def test_second_run_does_nothing(repo):
    stamp_core.stamp(repo.path)
    assert stamp_core.stamp(repo.path) == []


def test_one_bad_rule_stamps_nothing(repo):
    (repo.path / "detection-rules/bad.yml").write_bytes(b"[\n")
    with pytest.raises(stamp_core.RuleError, match="bad.yml"):
        stamp_core.stamp(repo.path)
    assert disk(repo, rule_path("a")) == rule_yaml("a", tier=None)
    assert stamp_core.main(["--repo", str(repo.path)]) == 1


def test_stamped_repo_syncs_and_passes_tier_check(repo):
    """Before stamping, the unstamped rules already in the public repo are demotions; after, they're updates."""
    public = {p: e for p, e in read_tree(str(repo.path), "HEAD", RULES_DIR).items() if p != rule_path("ent")}
    with pytest.raises(ProjectionError):
        project(read_tree(str(repo.path), "HEAD", RULES_DIR), public)

    base = repo.head()
    stamp_core.main(["--repo", str(repo.path)])
    repo.commit({})
    head_files = read_tree(str(repo.path), "HEAD", RULES_DIR)
    plan = project(head_files, public)
    assert sorted(plan.updated) == sorted([rule_path("a"), rule_path("b"), "detection-rules/noid"])
    assert plan.removed == [] and plan.added == []
    assert all(parse_rule(p, e.content).is_public for p, e in plan.desired.items())
    assert tier_check.check(read_tree(str(repo.path), base, RULES_DIR), head_files, non_core_enabled=False) == []
