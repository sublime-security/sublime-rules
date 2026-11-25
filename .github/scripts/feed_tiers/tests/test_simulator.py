"""The simulator's own behavior, so the end-to-end tests can't pass because the simulator is too lenient."""

from datetime import datetime, timezone

import pytest

from gha import expressions
from gha.world import OLD_NAME, PRIVATE, PUBLIC, World
from helpers import rule_path, rule_yaml

CTX = {
    "github": {"repository": "o/r", "event_name": "push", "event": {"merge_group": {"base_sha": "abc"}}},
    "inputs": {"dry_run": True, "as_of": ""},
    "steps": {"sync": {"outputs": {"changed": "true"}}},
    "vars": {},
}


class TestExpressions:
    @pytest.mark.parametrize(
        "expr, value",
        [
            ("github.repository == 'o/r'", True),
            ("github.repository == 'O/R'", True),  # case-insensitive
            ("github.repository == 'o/other'", False),
            ("github.event.merge_group.base_sha || 'HEAD^1'", "abc"),
            ("github.event.pull_request.base.sha || 'HEAD^1'", "HEAD^1"),
            ("steps.sync.outputs.changed == 'true'", True),
            ("steps.missing.outputs.changed == 'true'", False),
            ("!inputs.dry_run", False),
            ("inputs.missing", None),
            ("vars.NON_CORE_TIERS_ENABLED", None),
            ("inputs.dry_run && 'yes' || 'no'", "yes"),
            ("(1 == 1) && !(2 == 3)", True),
            ("'it''s'", "it's"),
            ("true == 1", True),
            ("null == 0", True),
            ("'' == false", True),
            ("contains('abc', 'B')", True),
            ("startsWith(github.repository, 'o/')", True),
        ],
    )
    def test_evaluate(self, expr, value):
        assert expressions.evaluate(expr, CTX) == value

    def test_render(self):
        assert expressions.render("x=${{ inputs.dry_run }} y=${{ inputs.missing }}", CTX) == "x=true y="

    @pytest.mark.parametrize(
        "cond, status, result",
        [
            (None, "success", True),
            (None, "failure", False),
            ("steps.sync.outputs.changed == 'true'", "success", True),
            ("steps.sync.outputs.changed == 'true'", "failure", False),
            ("always()", "failure", True),
            ("failure()", "failure", True),
            ("${{ github.repository == 'o/r' }}", "success", True),
        ],
    )
    def test_condition(self, cond, status, result):
        assert expressions.condition(cond, CTX, status) is result

    def test_rejects_garbage(self):
        with pytest.raises(expressions.ExpressionError):
            expressions.evaluate("a ==", CTX)


@pytest.fixture
def world(tmp_path):
    w = World(tmp_path / "w", datetime(2027, 1, 1, tzinfo=timezone.utc), {rule_path("a"): rule_yaml("a")})
    w.cutover()
    return w


class TestAccessRules:
    @pytest.mark.parametrize(
        "credential, allowed",
        [
            ("admin", True),
            ("deploy-key:mirror-deploy-key-1", True),
            ("deploy-key:wrong", False),
            ("merge", False),
            ("dev:x", False),
            ("token:sublime-security/sublime-rules:contents=write", False),
            ("token:sublime-security/sublime-rules-enterprise:contents=write", False),
            ("", False),
        ],
    )
    def test_public_main(self, world, credential, allowed):
        if allowed:
            world.commit(PUBLIC, {"x": "1"}, credential=credential)
        else:
            with pytest.raises(PermissionError):
                world.commit(PUBLIC, {"x": "1"}, credential=credential)

    @pytest.mark.parametrize(
        "credential, ref, allowed",
        [
            ("merge", "main", True),
            ("dev:x", "main", False),
            (f"token:{PRIVATE}:contents=write", "main", False),
            (f"token:{PRIVATE}:contents=write", "auto/x", True),
            (f"token:{PRIVATE}:contents=read", "auto/x", False),
            (f"token:{PUBLIC}:contents=write", "auto/x", False),
            ("deploy-key:mirror-deploy-key-1", "auto/x", False),
            ("dev:x", "feature", True),
        ],
    )
    def test_private(self, world, credential, ref, allowed):
        if allowed:
            world.commit(PRIVATE, {"x": "1"}, credential=credential, ref=ref)
        else:
            with pytest.raises(PermissionError):
                world.commit(PRIVATE, {"x": "1"}, credential=credential, ref=ref)

    def test_rename_moves_settings(self, tmp_path):
        w = World(tmp_path / "w", datetime(2027, 1, 1, tzinfo=timezone.utc), {})
        w.vars[OLD_NAME]["X"] = "1"
        w.cutover()
        assert w.vars[PRIVATE] == {"X": "1"} and w.vars[PUBLIC] == {}


class TestRunner:
    def test_job_guard_skips_other_repos(self, world):
        assert world.run_workflow("sync-public.yml", "schedule", repo=PRIVATE).conclusion == "success"

    def test_unknown_trigger_is_an_error(self, world):
        with pytest.raises(AssertionError):
            world.run_workflow("sync-public.yml", "pull_request")

    def test_unknown_input_is_an_error(self, world):
        with pytest.raises(AssertionError):
            world.run_workflow("sync-public.yml", "workflow_dispatch", inputs={"nope": 1})

    def test_failed_step_skips_the_rest(self, world):
        world.commit(PRIVATE, {rule_path("bad"): b"feed_tier: x\n"}, credential="merge")
        run = world.sync()
        assert [s.outcome for s in run.steps][-3:] == ["failure", "skipped", "skipped"]

    def test_workflow_is_read_from_the_triggering_commit(self, world):
        # A PR that edits the workflow runs its own copy, as on GitHub. The environment still withholds the secret.
        world.commit(PRIVATE, {".github/workflows/sync-public.yml": b"on: [workflow_dispatch]\njobs:\n  x:\n    runs-on: x\n    steps:\n      - run: echo replaced\n"}, credential="dev:x", ref="feature")
        run = world.run_workflow("sync-public.yml", "workflow_dispatch", ref="refs/heads/feature")
        assert run.ok and "replaced" in run.log
