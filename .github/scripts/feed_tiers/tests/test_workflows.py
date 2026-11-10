"""Static checks on the workflow files: the security-relevant settings can't drift without a test failing."""

import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[4]
WORKFLOWS = ROOT / ".github" / "workflows"
PRIVATE = "sublime-security/sublime-rules-enterprise"


def load(name):
    return yaml.safe_load((WORKFLOWS / name).read_text())


def job(name):
    (only,) = load(name)["jobs"].values()
    return only


def steps(name):
    return job(name)["steps"]


ALL = ["sync-public.yml", "promote-delayed.yml", "tier-check.yml", "feed-tiers-tests.yml"]


@pytest.mark.parametrize("name", ALL)
def test_actions_are_pinned_to_shas(name):
    for step in steps(name):
        if "uses" in step:
            assert re.fullmatch(r"[\w./-]+@[0-9a-f]{40}", step["uses"]), step["uses"]


@pytest.mark.parametrize("name", ALL)
def test_permissions_are_declared(name):
    assert "permissions" in load(name)


@pytest.mark.parametrize("name", ALL)
def test_no_expressions_inside_run(name):
    # Expressions go through env, so nothing from an event can be interpolated into a shell script.
    for step in steps(name):
        assert "${{" not in step.get("run", ""), step


@pytest.mark.parametrize("name", ["sync-public.yml", "promote-delayed.yml"])
def test_guarded_until_the_rename(name):
    assert job(name)["if"] == f"github.repository == '{PRIVATE}'"


def test_tier_check_is_not_guarded():
    assert "if" not in job("tier-check.yml")


def test_sync_permissions_and_credentials():
    workflow = load("sync-public.yml")
    assert workflow["permissions"] == {"contents": "read"}
    assert job("sync-public.yml")["environment"] == "public-mirror"
    private_checkout, public_checkout = [s for s in steps("sync-public.yml") if s.get("uses", "").startswith("actions/checkout@")]
    assert private_checkout["with"]["persist-credentials"] is False
    assert private_checkout["with"]["ref"] == "main"
    assert public_checkout["with"]["repository"] == "sublime-security/sublime-rules"
    assert public_checkout["with"]["ssh-key"] == "${{ secrets.PUBLIC_MIRROR_DEPLOY_KEY }}"
    assert workflow["concurrency"] == {"group": "public-mirror", "cancel-in-progress": False}


def test_sync_pushes_only_after_the_guard():
    names = [s.get("name") for s in steps("sync-public.yml")]
    assert names.index("Leak guard") < names.index("Push") == len(names) - 1
    assert steps("sync-public.yml")[-1]["run"].strip() == "git push origin HEAD:refs/heads/main"


def test_sync_triggers():
    on = load("sync-public.yml")[True]
    assert on["push"] == {"branches": ["main"]}
    assert "schedule" in on and "workflow_dispatch" in on


def test_promote_permissions():
    assert load("promote-delayed.yml")["permissions"] == {"contents": "write", "pull-requests": "write", "actions": "write"}
    assert "environment" not in job("promote-delayed.yml")
    assert "secrets." not in (WORKFLOWS / "promote-delayed.yml").read_text()


def test_tier_check_has_no_secrets_and_reads_only():
    assert load("tier-check.yml")["permissions"] == {"contents": "read"}
    assert "secrets." not in (WORKFLOWS / "tier-check.yml").read_text()
    on = load("tier-check.yml")[True]
    assert set(on) == {"pull_request", "merge_group", "workflow_dispatch"}
    assert "pull_request_target" not in on


def test_dispatched_workflows_accept_dispatch():
    import promote

    for name in promote.REQUIRED_CHECK_WORKFLOWS:
        assert "workflow_dispatch" in load(name)[True], name


@pytest.mark.parametrize("name", ALL)
def test_referenced_scripts_exist(name):
    text = (WORKFLOWS / name).read_text()
    for script in re.findall(r"(?:private/)?(\.github/scripts/feed_tiers/[\w./-]+)", text):
        assert (ROOT / script.rstrip(".")).exists(), script
