"""End to end: the real workflow files and scripts, run by the simulated GitHub in gha/world.py.

Each test starts from today's repo (public, named sublime-rules), usually runs the cutover, and then drives the
private and public repos through PRs, merges, scheduled runs and mistakes. After every successful sync, the public
rules must be exactly the private rules whose tier is core or absent.
"""

import random
from datetime import datetime, timedelta, timezone

import pytest

from gha.world import MIRROR_KEY, OLD_NAME, PRIVATE, PUBLIC, MergeBlocked, World
from helpers import rule_id, rule_path, rule_yaml
from rules import CORE, CORE_WITH_DELAY, ENTERPRISE_ONLY, parse_rule

START = datetime(2027, 1, 4, 15, 0, tzinfo=timezone.utc)

LEGACY = {
    rule_path("legacy_a"): rule_yaml("legacy_a"),
    rule_path("legacy_b"): rule_yaml("legacy_b"),
    "detection-rules/attachment_no_extension": rule_yaml("no_extension", rule_id_=None) + b"---\n",
    "yara/sig.yar": b"rule x { condition: true }\n",
    "README.md": b"Sublime rules\n",
}


@pytest.fixture
def before_rename(tmp_path):
    return World(tmp_path / "world", START, LEGACY)


@pytest.fixture
def world(before_rename):
    """After the cutover, with non-core tiers open (rollout phase 6)."""
    before_rename.cutover()
    before_rename.vars[PRIVATE]["NON_CORE_TIERS_ENABLED"] = "true"
    return before_rename


def expected_public(world):
    return {p: c for p, c in world.files(PRIVATE).items() if parse_rule(p, c).is_public}


def assert_in_sync(world):
    assert world.files(PUBLIC) == expected_public(world)


def merge(world, files, title="Change rules", **kwargs):
    number = world.open_pr(files, title=title, **kwargs)
    world.merge_pr(number)
    return number


def runs(world, workflow):
    return [r for r in world.runs if r.workflow == workflow]


def last(world, workflow):
    return runs(world, workflow)[-1]


def open_promotions(world):
    return [p for p in world.prs(state="open") if p["head"].startswith("auto/promote-core/")]


def delayed(name):
    return {rule_path(name): rule_yaml(name, tier=CORE_WITH_DELAY)}


class TestBeforeTheRename:
    def test_sync_and_promote_are_inert(self, before_rename):
        world = before_rename
        assert world.run_workflow("sync-public.yml", "push", repo=OLD_NAME).conclusion == "skipped"
        assert world.run_workflow("sync-public.yml", "schedule", repo=OLD_NAME).conclusion == "skipped"
        assert world.run_workflow("promote-delayed.yml", "schedule", repo=OLD_NAME).conclusion == "skipped"

    def test_tier_check_only_allows_core(self, before_rename):
        world = before_rename
        for tier in (CORE_WITH_DELAY, ENTERPRISE_ONLY):
            number = world.open_pr({rule_path(f"new_{tier}"): rule_yaml(f"new_{tier}", tier=tier)}, repo=OLD_NAME)
            assert last(world, "tier-check.yml").conclusion == "failure"
            with pytest.raises(MergeBlocked):
                world.merge_pr(number)
            world.close_pr(number)

    def test_core_rules_merge_as_today(self, before_rename):
        world = before_rename
        number = world.open_pr({rule_path("new"): rule_yaml("new", tier=CORE)}, repo=OLD_NAME)
        assert last(world, "tier-check.yml").ok
        world.merge_pr(number)
        assert rule_path("new") in world.files(OLD_NAME)

    def test_rules_with_no_tier_must_say_core(self, before_rename):
        world = before_rename
        number = world.open_pr({rule_path("new"): rule_yaml("new", tier=None)}, repo=OLD_NAME)
        assert "set feed_tier: core" in last(world, "tier-check.yml").log
        with pytest.raises(MergeBlocked):
            world.merge_pr(number)

    def test_demotion_is_blocked_even_now(self, before_rename):
        world = before_rename
        world.vars[OLD_NAME]["NON_CORE_TIERS_ENABLED"] = "true"
        number = world.open_pr({rule_path("legacy_a"): rule_yaml("legacy_a", tier=ENTERPRISE_ONLY)}, repo=OLD_NAME)
        assert "never demoted" in last(world, "tier-check.yml").log
        with pytest.raises(MergeBlocked):
            world.merge_pr(number)


class TestCutover:
    def test_first_sync_makes_no_commit(self, world):  # S21
        bootstrap = world.head(PUBLIC)
        run = world.sync()
        assert run.ok, run
        assert run.step("Push").outcome == "skipped"
        assert world.head(PUBLIC) == bootstrap
        assert_in_sync(world)

    def test_public_history_is_the_private_history(self, world):
        private_main = world.head(PRIVATE)
        assert world.log(PUBLIC)[1:] == world.log(PRIVATE)
        assert world.log(PUBLIC)[1] == private_main

    def test_bootstrap_removed_the_workflows(self, world):
        assert world.files(PUBLIC, prefix=".github") == {}
        assert world.files(PRIVATE, prefix=".github/workflows") != {}

    def test_workflows_switch_on_after_the_rename(self, world):
        assert world.sync().conclusion == "success"
        assert world.promote().conclusion == "success"


class TestStandardUse:
    def test_core_rule_is_public_on_merge(self, world):  # S2
        merge(world, {rule_path("new"): rule_yaml("New rule", tier=CORE)})
        run = last(world, "sync-public.yml")
        assert run.event == "push" and run.ok, run
        assert run.step("Push").outcome == "success"
        assert rule_path("new") in world.files(PUBLIC)
        assert_in_sync(world)

    def test_public_commit_identity_and_trailer(self, world):  # S20
        merge(world, {rule_path("new"): rule_yaml("New rule", tier=CORE)}, author=("Dana Dev", "dana@example.com"))
        author, committer = world.log(PUBLIC, fmt="%an <%ae>%x00%cn <%ce>")[0].split("\0")
        body = world.messages(PUBLIC)[0]
        mirror = "Sublime Rules Mirror <sublime-rules-mirror@users.noreply.github.com>"
        assert (author, committer) == (mirror, mirror)
        assert f"Source-Commit: {world.head(PRIVATE)}" in body
        assert world.log(PUBLIC, fmt="%cI")[0] == START.isoformat().replace("+00:00", "Z")

    def test_enterprise_only_is_never_public(self, world):  # S3
        merge(world, {rule_path("secret"): rule_yaml("Secret rule", tier=ENTERPRISE_ONLY)})
        for _ in range(3):
            world.advance(400)
            assert world.promote().ok
            assert world.sync().ok
        assert rule_path("secret") not in world.files(PUBLIC)
        assert world.prs(state="open") == []
        assert_in_sync(world)

    def test_legacy_rule_edit_syncs(self, world):  # S1
        merge(world, {rule_path("legacy_a"): rule_yaml("legacy_a", source="type.outbound")})
        assert world.files(PUBLIC)[rule_path("legacy_a")] == rule_yaml("legacy_a", source="type.outbound")

    def test_edit_to_private_rule_makes_no_public_commit(self, world):
        merge(world, {rule_path("secret"): rule_yaml("secret", tier=ENTERPRISE_ONLY)})
        head = world.head(PUBLIC)
        merge(world, {rule_path("secret"): rule_yaml("secret", tier=ENTERPRISE_ONLY, source="changed")})
        assert last(world, "sync-public.yml").step("Push").outcome == "skipped"
        assert world.head(PUBLIC) == head

    def test_delete_propagates(self, world):  # S10
        merge(world, {rule_path("legacy_b"): None})
        assert rule_path("legacy_b") not in world.files(PUBLIC)
        assert_in_sync(world)

    def test_rename_is_one_public_commit(self, world):  # S14
        head = world.head(PUBLIC)
        merge(world, {rule_path("legacy_a"): None, rule_path("renamed"): rule_yaml("legacy_a")})
        assert world.log(PUBLIC)[1] == head
        files = world.files(PUBLIC)
        assert rule_path("renamed") in files and rule_path("legacy_a") not in files

    def test_mixed_pr(self, world):
        merge(
            world,
            {
                rule_path("c"): rule_yaml("c", tier=CORE),
                rule_path("d"): rule_yaml("d", tier=CORE_WITH_DELAY),
                rule_path("e"): rule_yaml("e", tier=ENTERPRISE_ONLY),
                rule_path("legacy_b"): None,
                rule_path("legacy_a"): rule_yaml("legacy_a", tier=CORE),
            },
        )
        assert_in_sync(world)

    def test_sync_twice_is_a_no_op(self, world):  # S16
        merge(world, {rule_path("new"): rule_yaml("new", tier=CORE)})
        head = world.head(PUBLIC)
        assert world.sync().ok and world.sync().ok
        assert world.head(PUBLIC) == head

    def test_private_names_never_reach_the_public_repo(self, world):  # S17
        merge(
            world,
            {rule_path("acme_secret"): rule_yaml("ACME secret detection", tier=ENTERPRISE_ONLY), rule_path("visible"): rule_yaml("Visible", tier=CORE)},
            title="Add ACME secret detection and Visible",
        )
        latest = world.messages(PUBLIC)[0]
        assert "Visible" in latest
        everything_since_cutover = "\n".join(world.messages(PUBLIC)[:2])
        assert "ACME" not in everything_since_cutover and "acme" not in everything_since_cutover
        everything = b"".join(world.files(PUBLIC, prefix="detection-rules").values())
        assert b"ACME" not in everything

    def test_only_detection_rules_are_mirrored(self, world):
        merge(world, {"yara/sig.yar": b"changed\n", "README.md": b"private readme\n", "insights/x.yml": b"a: 1\n", rule_path("n"): rule_yaml("n", tier=CORE)})
        assert world.files(PUBLIC, prefix="yara") == {"yara/sig.yar": b"rule x { condition: true }\n"}
        assert world.files(PUBLIC, prefix="insights") == {}
        assert world.files(PUBLIC, prefix=".github") == {}

    def test_dry_run_dispatch(self, world):
        merge(world, {rule_path("new"): rule_yaml("new", tier=CORE)}, )
        world.commit(PRIVATE, {rule_path("other"): rule_yaml("other")}, credential="merge")
        head = world.head(PUBLIC)
        run = world.sync(event="workflow_dispatch", dry_run=True)
        assert run.ok and run.step("Push").outcome == "skipped"
        assert "Would sync" in run.step("Project private rules onto the public repo").log
        assert world.head(PUBLIC) == head


class TestPromotion:
    def test_full_cycle(self, world):  # S4, S5
        merge(world, delayed("delayed"))
        assert rule_path("delayed") not in world.files(PUBLIC)

        world.advance(days=89, hours=23)
        assert world.promote().ok
        assert open_promotions(world) == []

        world.advance(hours=1)
        run = world.promote()
        assert run.ok, run
        (pr,) = open_promotions(world)
        assert pr["head"] == f"auto/promote-core/{rule_id('delayed')}"
        assert (pr["opened_by"], pr["labels"], pr["base"]) == ("github-actions[bot]", ["auto-promote"], "main")
        assert {d["workflow"] for d in world.dispatches()} == {"rule-validate.yml", "tier-check.yml"}
        branch_head = world.head(PRIVATE, pr["head"])
        assert world.checks[branch_head] == {"tier-check": "success", "rule-validate": "success"}

        assert rule_path("delayed") not in world.files(PUBLIC)
        world.merge_pr(pr["number"])
        assert world.files(PUBLIC)[rule_path("delayed")] == rule_yaml("delayed", tier=CORE)
        assert_in_sync(world)
        assert world.promote().ok and open_promotions(world) == []

    def test_promotion_pr_changes_one_line(self, world):
        merge(world, delayed("delayed"))
        world.advance(90)
        world.promote()
        (pr,) = open_promotions(world)
        before = world.files(PRIVATE)[rule_path("delayed")]
        after = world.files(PRIVATE, ref=pr["head"])[rule_path("delayed")]
        assert after == before.replace(b"feed_tier: core_with_delay", b"feed_tier: core")
        main = world.files(PRIVATE, prefix="")
        branch = world.files(PRIVATE, prefix="", ref=pr["head"])
        assert {p for p in set(main) | set(branch) if main.get(p) != branch.get(p)} == {rule_path("delayed")}

    def test_promote_never_moves_main(self, world):
        merge(world, delayed("delayed"))
        main = world.head(PRIVATE)
        world.advance(100)
        world.promote()
        assert world.head(PRIVATE) == main

    def test_no_duplicate_pr_while_open(self, world):  # S6
        merge(world, delayed("delayed"))
        world.advance(90)
        world.promote()
        world.advance(1)
        world.promote()
        world.advance(30)
        world.promote()
        assert len(world.prs()) == 2  # the PR that added it, and one promotion
        assert len(world.dispatches()) == 2

    def test_cannot_merge_before_its_checks_run(self, world):
        merge(world, delayed("delayed"))
        world.advance(90)
        run = world.run_workflow("promote-delayed.yml", "workflow_dispatch", inputs={"as_of": world.clock.isoformat()})
        assert run.ok
        (pr,) = open_promotions(world)
        with pytest.raises(MergeBlocked, match="required checks"):
            world.merge_pr(pr["number"])
        world.run_dispatches()
        world.merge_pr(pr["number"])

    def test_promoted_by_hand_early(self, world):  # S7
        merge(world, delayed("delayed"))
        world.advance(3)
        merge(world, {rule_path("delayed"): rule_yaml("delayed", tier=CORE)})
        assert rule_path("delayed") in world.files(PUBLIC)
        world.advance(200)
        world.promote()
        assert open_promotions(world) == []

    def test_enterprise_only_to_core_by_hand(self, world):  # S8
        merge(world, {rule_path("e"): rule_yaml("e", tier=ENTERPRISE_ONLY)})
        merge(world, {rule_path("e"): rule_yaml("e", tier=CORE)})
        assert rule_path("e") in world.files(PUBLIC)

    def test_rename_keeps_the_clock(self, world):  # S9
        merge(world, delayed("delayed"))
        world.advance(50)
        merge(world, {rule_path("delayed"): None, rule_path("moved"): rule_yaml("delayed", tier=CORE_WITH_DELAY)})
        world.advance(39)
        world.promote()
        assert open_promotions(world) == []
        world.advance(1)
        world.promote()
        (pr,) = open_promotions(world)
        world.merge_pr(pr["number"])
        assert rule_path("moved") in world.files(PUBLIC)

    def test_enterprise_only_first_then_delayed(self, world):  # S18
        merge(world, {rule_path("x"): rule_yaml("x", tier=ENTERPRISE_ONLY)})
        world.advance(200)
        merge(world, {rule_path("x"): rule_yaml("x", tier=CORE_WITH_DELAY)})
        world.advance(0.1)
        world.promote()
        assert len(open_promotions(world)) == 1

    def test_decline_by_changing_to_enterprise_only(self, world):
        merge(world, delayed("delayed"))
        world.advance(90)
        world.promote()
        (pr,) = open_promotions(world)
        world.push_to_pr(pr["number"], {rule_path("delayed"): rule_yaml("delayed", tier=ENTERPRISE_ONLY)}, author=("Reviewer", "r@example.com"))
        world.merge_pr(pr["number"])
        assert rule_path("delayed") not in world.files(PUBLIC)
        world.advance(30)
        world.promote()
        assert open_promotions(world) == []
        assert_in_sync(world)

    def test_closed_pr_is_opened_again(self, world):
        merge(world, delayed("delayed"))
        world.advance(90)
        world.promote()
        (pr,) = open_promotions(world)
        world.close_pr(pr["number"])
        world.advance(1)
        world.promote()
        (again,) = open_promotions(world)
        assert again["number"] != pr["number"]
        world.merge_pr(again["number"])
        assert rule_path("delayed") in world.files(PUBLIC)

    def test_stale_promotion_pr_merges_onto_newer_main(self, world):
        merge(world, delayed("delayed"))
        world.advance(90)
        world.promote()
        (pr,) = open_promotions(world)
        merge(world, {rule_path("delayed"): rule_yaml("delayed", tier=CORE_WITH_DELAY, source="improved"), rule_path("x"): rule_yaml("x", tier=CORE)})
        world.merge_pr(pr["number"])
        assert world.files(PUBLIC)[rule_path("delayed")] == rule_yaml("delayed", tier=CORE, source="improved")
        assert_in_sync(world)

    def test_promotion_pr_for_deleted_rule_cannot_merge(self, world):
        merge(world, delayed("delayed"))
        world.advance(90)
        world.promote()
        (pr,) = open_promotions(world)
        merge(world, {rule_path("delayed"): None})
        with pytest.raises(MergeBlocked):
            world.merge_pr(pr["number"])
        world.close_pr(pr["number"])
        world.promote()
        assert open_promotions(world) == []
        assert_in_sync(world)

    def test_many_due_at_once(self, world):
        merge(world, {**delayed("a"), **delayed("b"), **delayed("c")})
        world.advance(90)
        world.promote()
        prs = open_promotions(world)
        assert len(prs) == 3
        for pr in prs:
            world.merge_pr(pr["number"])
        assert {rule_path(n) for n in "abc"} <= set(world.files(PUBLIC))
        assert_in_sync(world)

    def test_dry_run(self, world):
        merge(world, delayed("delayed"))
        world.advance(90)
        run = world.promote(dry_run=True)
        assert run.ok and "would open a PR" in run.log
        assert open_promotions(world) == [] and world.dispatches() == []

    def test_scheduled_run_uses_the_real_clock(self, tmp_path):
        now = datetime.now(timezone.utc)
        world = World(tmp_path / "w", now - timedelta(days=100), LEGACY)
        world.cutover()
        world.vars[PRIVATE]["NON_CORE_TIERS_ENABLED"] = "true"
        merge(world, delayed("delayed"))
        world.clock = now
        run = world.run_workflow("promote-delayed.yml", "schedule")
        assert run.ok, run
        assert len(open_promotions(world)) == 1

    def test_needs_the_actions_pr_setting(self, world):
        world.set_actions_can_create_prs(PRIVATE, False)
        merge(world, delayed("delayed"))
        world.advance(90)
        run = world.promote()
        assert run.conclusion == "failure"
        assert "not permitted to create or approve pull requests" in run.log
        assert open_promotions(world) == []

    def test_needs_the_label(self, world):
        world._save_state({**world._state(), "labels": {}})
        merge(world, delayed("delayed"))
        world.advance(90)
        run = world.promote()
        assert run.conclusion == "failure" and "auto-promote' not found" in run.log


class TestFailsClosed:
    def test_demotion_pr_is_blocked(self, world):  # S11
        world.vars[PRIVATE]["NON_CORE_TIERS_ENABLED"] = "true"
        number = world.open_pr({rule_path("legacy_a"): rule_yaml("legacy_a", tier=ENTERPRISE_ONLY)})
        assert last(world, "tier-check.yml").conclusion == "failure"
        with pytest.raises(MergeBlocked):
            world.merge_pr(number)

    def test_demotion_with_rename_is_blocked(self, world):  # S12
        world.vars[PRIVATE]["NON_CORE_TIERS_ENABLED"] = "true"
        number = world.open_pr({rule_path("legacy_a"): None, rule_path("sneaky"): rule_yaml("legacy_a", tier=CORE_WITH_DELAY)})
        with pytest.raises(MergeBlocked):
            world.merge_pr(number)

    def test_demotion_that_reaches_main_stops_the_sync(self, world):  # S13
        merge(world, {rule_path("good"): rule_yaml("good", tier=CORE)})
        public_head = world.head(PUBLIC)
        world.commit(PRIVATE, {rule_path("legacy_a"): rule_yaml("legacy_a", tier=ENTERPRISE_ONLY), rule_path("other"): rule_yaml("other", tier=CORE)}, credential="merge")
        run = world.sync()
        assert run.conclusion == "failure"
        assert "never demoted" in run.log and "Nothing was synced" in run.log
        assert run.step("Push").outcome == "skipped"
        assert world.head(PUBLIC) == public_head
        assert rule_path("legacy_a") in world.files(PUBLIC)

        merge(world, {rule_path("legacy_a"): rule_yaml("legacy_a", tier=CORE)})
        assert last(world, "sync-public.yml").ok
        assert_in_sync(world)

    def test_unknown_tier_on_main_blocks_everything(self, world):  # S15
        public_head = world.head(PUBLIC)
        world.commit(PRIVATE, {rule_path("typo"): rule_yaml("typo", tier="enterprise"), rule_path("fine"): rule_yaml("fine", tier=CORE)}, credential="merge")
        run = world.sync()
        assert run.conclusion == "failure" and "feed_tier must be one of" in run.log
        assert world.head(PUBLIC) == public_head

    def test_unknown_tier_pr_is_blocked(self, world):
        number = world.open_pr({rule_path("typo"): rule_yaml("typo", tier="Core")})
        with pytest.raises(MergeBlocked):
            world.merge_pr(number)

    def test_merge_queue_catches_what_each_pr_alone_hides(self, world):
        one = world.open_pr({rule_path("one"): rule_yaml("one", tier=CORE, rule_id_="same-id")})
        two = world.open_pr({rule_path("two"): rule_yaml("two", tier=CORE, rule_id_="same-id")})
        assert last(world, "tier-check.yml").ok  # each alone is fine
        world.merge_pr(one)
        with pytest.raises(MergeBlocked, match="merge queue"):
            world.merge_pr(two)
        assert_in_sync(world)

    def test_new_rule_with_no_tier_stays_private_until_promoted(self, world):
        content = rule_yaml("forgot", tier=None)
        world.merge_pr(world.open_pr({rule_path("forgot"): content}))
        assert rule_path("forgot") not in world.files(PUBLIC)
        assert_in_sync(world)

        world.advance(90)
        assert world.promote().ok
        (pr,) = open_promotions(world)
        promoted = content.replace(b'id: "', b'feed_tier: core\nid: "')
        assert world.files(PRIVATE, ref=pr["head"])[rule_path("forgot")] == promoted
        assert world.checks[world.head(PRIVATE, pr["head"])] == {"tier-check": "success", "rule-validate": "success"}
        world.merge_pr(pr["number"])
        assert world.files(PUBLIC)[rule_path("forgot")] == promoted
        assert_in_sync(world)

    def test_removing_the_core_line_is_blocked(self, world):
        number = world.open_pr({rule_path("legacy_a"): rule_yaml("legacy_a", tier=None)})
        assert "can't become core_with_delay (no feed_tier key)" in last(world, "tier-check.yml").log
        with pytest.raises(MergeBlocked):
            world.merge_pr(number)

    def test_canary_gate(self, world):
        world.vars[PRIVATE].pop("NON_CORE_TIERS_ENABLED")
        number = world.open_pr({rule_path("e"): rule_yaml("e", tier=ENTERPRISE_ONLY)})
        with pytest.raises(MergeBlocked):
            world.merge_pr(number)
        world.vars[PRIVATE]["NON_CORE_TIERS_ENABLED"] = "true"
        world.push_to_pr(number, {})
        world.merge_pr(number)
        assert rule_path("e") not in world.files(PUBLIC)


class TestPublicRepoProtection:
    def test_stray_public_changes_are_reverted(self, world):  # S19
        world.commit(PUBLIC, {rule_path("stray"): rule_yaml("stray"), rule_path("legacy_a"): b"tampered\n"})
        assert world.sync().ok
        assert_in_sync(world)

    def test_only_the_deploy_key_can_push_to_public_main(self, world):
        with pytest.raises(PermissionError, match="dev may not update refs/heads/main"):
            world.commit(PUBLIC, {rule_path("x"): rule_yaml("x")}, credential="dev:someone")
        with pytest.raises(PermissionError, match="can't push"):
            world.commit(PUBLIC, {rule_path("x"): rule_yaml("x")}, credential=f"token:{PRIVATE}:contents=write")
        with pytest.raises(PermissionError, match="isn't registered"):
            world.commit(PUBLIC, {rule_path("x"): rule_yaml("x")}, credential="deploy-key:some-other-key")
        world.commit(PUBLIC, {rule_path("x"): rule_yaml("x")}, credential=f"deploy-key:{MIRROR_KEY}")

    def test_nobody_pushes_private_main_directly(self, world):
        with pytest.raises(PermissionError):
            world.commit(PRIVATE, {rule_path("x"): rule_yaml("x")}, credential="dev:someone")
        with pytest.raises(PermissionError):
            world.commit(PRIVATE, {rule_path("x"): rule_yaml("x")}, credential=f"token:{PRIVATE}:contents=write")

    def test_missing_secret_cannot_push(self, tmp_path):
        world = World(tmp_path / "w", START, LEGACY)
        world.cutover(secret=None)
        merge(world, {rule_path("new"): rule_yaml("new", tier=CORE)})
        run = last(world, "sync-public.yml")
        assert run.conclusion == "failure" and "can't push" in run.step("Push").log
        assert rule_path("new") not in world.files(PUBLIC)

    def test_wrong_key_cannot_push(self, tmp_path):
        world = World(tmp_path / "w", START, LEGACY)
        world.cutover(secret="a-key-for-some-other-repo")
        merge(world, {rule_path("new"): rule_yaml("new", tier=CORE)})
        run = last(world, "sync-public.yml")
        assert run.conclusion == "failure" and "isn't registered" in run.step("Push").log

    def test_secret_only_on_main(self, world):
        world.commit(PRIVATE, {}, credential="dev:x", ref="feature")
        run = world.run_workflow("sync-public.yml", "workflow_dispatch", ref="refs/heads/feature")
        assert run.conclusion == "failure" and "environment protection rules" in run.reason

    def test_private_checkout_has_no_credential(self, world):
        def push_to_private(step, w):
            if step == "Leak guard":
                import subprocess
                workspace = sorted((w.root / "runs").iterdir())[-1] / "workspace" / "private"
                result = subprocess.run(["git", "push", "origin", "HEAD:refs/heads/evil"], cwd=workspace, capture_output=True, text=True)
                assert "authentication required" in result.stderr

        merge(world, {rule_path("new"): rule_yaml("new", tier=CORE)}, )
        world.commit(PRIVATE, {rule_path("n2"): rule_yaml("n2")}, credential="merge")
        assert world.run_workflow("sync-public.yml", "schedule", before_step=push_to_private).ok


class TestMissedAndRacingRuns:
    def test_missed_runs_are_healed_by_the_schedule(self, world):
        head = world.head(PUBLIC)
        for name in ("one", "two", "three"):
            world.merge_pr(world.open_pr({rule_path(name): rule_yaml(name, tier=CORE)}), run_push_workflows=False)
        assert world.head(PUBLIC) == head
        assert world.sync().ok
        assert world.log(PUBLIC)[1] == head  # one commit for all three
        assert_in_sync(world)

    def test_delayed_run_for_an_older_commit_syncs_the_latest(self, world):
        first = world.merge_pr(world.open_pr({rule_path("one"): rule_yaml("one", tier=CORE)}), run_push_workflows=False)
        world.merge_pr(world.open_pr({rule_path("two"): rule_yaml("two", tier=CORE)}), run_push_workflows=False)
        run = world.run_workflow("sync-public.yml", "push", sha=first)
        assert run.ok
        assert {rule_path("one"), rule_path("two")} <= set(world.files(PUBLIC))
        assert_in_sync(world)

    def test_public_moved_during_the_run(self, world):
        def tamper(step, w):
            if step == "Push":
                w.commit(PUBLIC, {"CONTRIBUTING.md": "changed meanwhile\n"})

        world.merge_pr(world.open_pr({rule_path("one"): rule_yaml("one", tier=CORE)}), run_push_workflows=False)
        run = world.run_workflow("sync-public.yml", "schedule", before_step=tamper)
        assert run.conclusion == "failure" and run.step("Push").outcome == "failure"
        assert rule_path("one") not in world.files(PUBLIC)
        assert world.sync().ok
        assert_in_sync(world)
        assert world.files(PUBLIC, prefix="")["CONTRIBUTING.md"] == b"changed meanwhile\n"

    def test_failed_sync_is_retried_by_the_next_merge(self, world):
        world.commit(PRIVATE, {rule_path("typo"): rule_yaml("typo", tier="nope")}, credential="merge")
        assert world.sync().conclusion == "failure"
        merge(world, {rule_path("typo"): rule_yaml("typo", tier=ENTERPRISE_ONLY), rule_path("ok"): rule_yaml("ok", tier=CORE)})
        assert last(world, "sync-public.yml").ok
        assert_in_sync(world)


class TestRandomWalk:
    """A long seeded run of PRs, promotions, bypasses and missed runs through the real workflows. After every
    successful sync the invariant holds, and a rule that was never public never appears in the public repo."""

    @pytest.mark.parametrize("seed", [1, 2, 3])
    def test_walk(self, world, seed):
        rng = random.Random(seed)
        world.vars[PRIVATE]["NON_CORE_TIERS_ENABLED"] = "true"
        names = [f"r{i}" for i in range(12)]
        ever_public = set(world.files(PUBLIC))

        def private_rules():
            return {p: parse_rule(p, c) for p, c in world.files(PRIVATE).items()}

        for step in range(25):
            current = private_rules()
            action = rng.choice(["add", "add", "edit", "promote_by_hand", "delete", "rename", "advance", "advance", "skip_sync"])
            name = rng.choice(names)
            path = rule_path(name)
            files = None
            if action == "add" and path not in current:
                files = {path: rule_yaml(name, tier=rng.choice([CORE, CORE_WITH_DELAY, ENTERPRISE_ONLY]))}
            elif action == "edit" and path in current:
                tier = current[path].tier
                files = {path: rule_yaml(name, tier=tier, source=f"edit {step}") if tier else rule_yaml(name, source=f"edit {step}")}
            elif action == "promote_by_hand" and path in current and not current[path].is_public:
                files = {path: rule_yaml(name, tier=rng.choice([CORE, ENTERPRISE_ONLY, CORE_WITH_DELAY]))}
            elif action == "delete" and path in current:
                files = {path: None}
            elif action == "rename" and path in current:
                new = rule_path(f"{name}_moved{step}")
                files = {path: None, new: world.files(PRIVATE)[path]}
            elif action == "advance":
                world.advance(rng.choice([1, 10, 45, 91]))
                assert world.promote().ok
                for pr in open_promotions(world):
                    if rng.random() < 0.7:
                        try:
                            world.merge_pr(pr["number"])
                        except MergeBlocked:
                            world.close_pr(pr["number"])
            if files:
                number = world.open_pr(files)
                try:
                    world.merge_pr(number, run_push_workflows=action != "skip_sync" and rng.random() < 0.8)
                except MergeBlocked:
                    world.close_pr(number)

            if rng.random() < 0.3 or step == 24:
                assert world.sync().ok
                assert_in_sync(world)
            for p, content in world.files(PUBLIC).items():
                ever_public.add(p)
                assert parse_rule(p, content).is_public
            for p, rule in private_rules().items():
                if rule.tier == ENTERPRISE_ONLY and p not in ever_public:
                    assert p not in world.files(PUBLIC)
