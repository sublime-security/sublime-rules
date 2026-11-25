"""default_tier.py against real git repos, with an in-memory GitHub."""

import pytest

import default_tier
from gittree import Entry, read_tree
from helpers import Repo, rule_id, rule_path, rule_yaml, run_git
from rules import CORE, CORE_WITH_DELAY, ENTERPRISE_ONLY, RULES_DIR, parse_rule
from tier_check import check

BRANCH = "alice/new-rule"


class FakeGitHub:
    def __init__(self):
        self.dispatches: list[tuple[str, str]] = []
        self.comments: list[tuple[int, str]] = []

    def dispatch_workflow(self, workflow, ref):
        self.dispatches.append((workflow, ref))

    def comment_pr(self, number, body):
        self.comments.append((number, body))


def entries(files: dict[str, bytes]) -> dict[str, Entry]:
    return {path: Entry("100644", content) for path, content in files.items()}


class TestMissingTiers:
    def test_new_rule_without_key_gets_the_default_above_id(self):
        content = rule_yaml("new", tier=None)
        result = default_tier.missing_tiers({}, entries({rule_path("new"): content}))
        assert result.skipped == []
        updated = result.updates[rule_path("new")].content
        assert updated == content.replace(b'id: "', b'feed_tier: core_with_delay\nid: "')
        assert parse_rule(rule_path("new"), updated).tier == CORE_WITH_DELAY

    @pytest.mark.parametrize("tier", [CORE, CORE_WITH_DELAY, ENTERPRISE_ONLY])
    def test_rules_with_a_key_are_left_alone(self, tier):
        result = default_tier.missing_tiers({}, entries({rule_path("new"): rule_yaml("new", tier=tier)}))
        assert result.updates == {} and result.skipped == []

    def test_unchanged_rules_are_left_alone(self):
        files = entries({rule_path("old"): rule_yaml("old", tier=None)})
        assert default_tier.missing_tiers(files, files).updates == {}

    def test_changed_rule_without_key_gets_it(self):
        base = entries({rule_path("old"): rule_yaml("old", tier=None)})
        head = entries({rule_path("old"): rule_yaml("old", tier=None, source="type.inbound\nand 1 == 1")})
        assert list(default_tier.missing_tiers(base, head).updates) == [rule_path("old")]

    def test_renamed_rule_without_key_gets_it(self):
        content = rule_yaml("old", tier=None)
        result = default_tier.missing_tiers(entries({rule_path("old"): content}), entries({rule_path("renamed"): content}))
        assert list(result.updates) == [rule_path("renamed")]

    def test_mode_is_kept(self):
        head = {rule_path("x"): Entry("100755", rule_yaml("x", tier=None))}
        assert default_tier.missing_tiers({}, head).updates[rule_path("x")].mode == "100755"

    def test_invalid_rules_are_left_to_tier_check(self):
        head = entries({rule_path("bad"): b"name: [unclosed\n", rule_path("caps"): rule_yaml("caps", tier="Core")})
        result = default_tier.missing_tiers({}, head)
        assert result.updates == {} and result.skipped == []

    def test_rule_the_line_cant_be_added_to_is_listed(self):
        # No id or source line, and a block scalar at the end with no final newline: appending would change it.
        content = b'name: "x"\nnotes: |\n  text'
        result = default_tier.missing_tiers({}, entries({rule_path("x"): content}))
        assert result.updates == {}
        assert [path for path, _ in result.skipped] == [rule_path("x")]

    def test_crlf_is_kept(self):
        content = rule_yaml("crlf", tier=None).replace(b"\n", b"\r\n")
        updated = default_tier.missing_tiers({}, entries({rule_path("crlf"): content})).updates[rule_path("crlf")].content
        assert b"feed_tier: core_with_delay\r\nid:" in updated and b"\n" not in updated.replace(b"\r\n", b"")

    def test_tier_never_changes(self):
        content = rule_yaml("new", tier=None)
        before = parse_rule(rule_path("new"), content)
        updated = default_tier.missing_tiers({}, entries({rule_path("new"): content})).updates[rule_path("new")].content
        assert parse_rule(rule_path("new"), updated).effective_tier == before.effective_tier == CORE_WITH_DELAY

    def test_core_rule_losing_its_key_is_a_demotion_not_a_default(self):
        base = entries({rule_path("old"): rule_yaml("old", tier=CORE)})
        head = entries({rule_path("old"): rule_yaml("old", tier=None)})
        result = default_tier.missing_tiers(base, head)
        assert result.updates == {} and result.skipped == []
        assert result.demoted == [f"old ({rule_path('old')})"]
        assert check(base, head, non_core_enabled=True) != []

    def test_moved_core_rule_losing_its_key_is_still_a_demotion(self):
        base = entries({rule_path("old"): rule_yaml("old", tier=CORE)})
        head = entries({rule_path("moved"): rule_yaml("old", tier=None)})
        result = default_tier.missing_tiers(base, head)
        assert result.updates == {} and result.demoted == [f"old ({rule_path('moved')})"]

    @pytest.mark.parametrize("tier", [None, CORE_WITH_DELAY, ENTERPRISE_ONLY])
    def test_rule_that_wasnt_core_still_gets_the_default(self, tier):
        base = entries({rule_path("old"): rule_yaml("old", tier=tier)})
        head = entries({rule_path("old"): rule_yaml("old", tier=None, source="type.inbound\nand 1 == 1")})
        result = default_tier.missing_tiers(base, head)
        assert list(result.updates) == [rule_path("old")] and result.demoted == []


class TestComment:
    def test_says_what_and_why(self):
        body = default_tier.comment_body([rule_path("a"), rule_path("b")], [], "abc123def456")
        assert body.startswith(default_tier.COMMENT_MARKER)
        assert "`feed_tier` was missing, so the default was applied." in body
        assert "abc123def456" in body and f"`{rule_path('a')}`" in body and f"`{rule_path('b')}`" in body
        assert "`core`" in body and "`enterprise_only`" in body and "90 days" in body
        assert "couldn't be added" not in body

    def test_lists_skipped_rules(self):
        body = default_tier.comment_body([rule_path("a")], [(rule_path("x"), "why")], "abc")
        assert f"- `{rule_path('x')}`: why" in body

    def test_lists_demoted_rules(self):
        body = default_tier.comment_body([rule_path("a")], [], "abc", ["old (detection-rules/old.yml)"])
        assert "demotion" in body and "- old (detection-rules/old.yml)" in body and "`feed_tier: core`" in body

    def test_no_demotion_section_without_demotions(self):
        assert "demotion" not in default_tier.comment_body([rule_path("a")], [], "abc")

    def test_commit_message_lists_paths(self):
        message = default_tier.commit_message([rule_path("a"), rule_path("b")])
        assert message.splitlines()[0] == "Add the default feed_tier: core_with_delay"
        assert f"- {rule_path('a')}" in message and f"- {rule_path('b')}" in message


@pytest.fixture
def origin(tmp_path):
    path = tmp_path / "origin.git"
    run_git(tmp_path, "init", "-q", "--bare", "-b", "main", str(path))
    return path


@pytest.fixture
def repo(tmp_path, origin):
    """main has one stamped core rule and one older rule with no key; the PR branch forks from there."""
    r = Repo(tmp_path / "work", name="github-actions[bot]", email="bot@example.com")
    r.commit({rule_path("legacy"): rule_yaml("legacy"), rule_path("unstamped"): rule_yaml("unstamped", tier=None)})
    run_git(r.path, "remote", "add", "origin", str(origin))
    run_git(r.path, "push", "-q", "origin", "main")
    run_git(r.path, "switch", "-q", "-c", BRANCH)
    return r


def push_branch(repo):
    run_git(repo.path, "push", "-q", "origin", f"HEAD:refs/heads/{BRANCH}")
    run_git(repo.path, "fetch", "-q", "origin")


def run(repo, github):
    return default_tier.add_defaults(str(repo.path), github, "origin/main", repo.head(), BRANCH, 7)


class TestAddDefaults:
    def test_pushes_one_commit_comments_and_starts_checks(self, repo, origin):
        content = rule_yaml("new", tier=None)
        repo.commit({rule_path("new"): content, rule_path("tiered"): rule_yaml("tiered", tier=CORE)})
        push_branch(repo)
        head = repo.head()
        github = FakeGitHub()

        result, commit = run(repo, github)

        pushed = run_git(origin, "rev-parse", f"refs/heads/{BRANCH}").strip()
        assert pushed == commit
        assert run_git(origin, "rev-parse", f"{pushed}^").strip() == head
        assert run_git(origin, "diff", "--name-only", head, pushed).split() == [rule_path("new")]
        added = run_git(origin, "show", f"{pushed}:{rule_path('new')}").encode()
        assert added == content.replace(b'id: "', b'feed_tier: core_with_delay\nid: "')
        assert run_git(origin, "log", "-1", "--format=%an%n%s", pushed).splitlines() == [
            "github-actions[bot]",
            "Add the default feed_tier: core_with_delay",
        ]
        assert github.dispatches == [("rule-validate.yml", BRANCH), ("tier-check.yml", BRANCH)]
        [(number, body)] = github.comments
        assert number == 7 and commit[:12] in body and rule_path("new") in body
        assert rule_path("tiered") not in body and rule_path("unstamped") not in body
        assert list(result.updates) == [rule_path("new")]

    def test_demotion_alone_pushes_nothing_and_tier_check_blocks_it(self, repo, origin):
        base = repo.head()
        repo.commit({rule_path("legacy"): rule_yaml("legacy", tier=None)})  # main has it as core
        push_branch(repo)
        head = repo.head()
        github = FakeGitHub()

        result, commit = run(repo, github)

        assert commit is None and result.updates == {}
        assert result.demoted == [f"legacy ({rule_path('legacy')})"]
        assert run_git(origin, "rev-parse", f"refs/heads/{BRANCH}").strip() == head
        assert github.dispatches == [] and github.comments == []
        [(path, problem)] = check(read_tree(repo.path, base, RULES_DIR), read_tree(repo.path, head, RULES_DIR), True)
        assert path == rule_path("legacy") and "never demoted" in problem

    def test_demotion_next_to_a_new_rule_is_named_in_the_comment(self, repo, origin):
        repo.commit({rule_path("legacy"): rule_yaml("legacy", tier=None), rule_path("new"): rule_yaml("new", tier=None)})
        push_branch(repo)
        github = FakeGitHub()

        _, commit = run(repo, github)

        assert run_git(origin, "show", f"{commit}:{rule_path('legacy')}").encode() == rule_yaml("legacy", tier=None)
        assert run_git(origin, "diff", "--name-only", f"{commit}^", commit).split() == [rule_path("new")]
        [(_, body)] = github.comments
        assert "demotion" in body and rule_path("legacy") in body

    def test_main_is_not_touched(self, repo, origin):
        main_before = run_git(origin, "rev-parse", "main").strip()
        repo.commit({rule_path("new"): rule_yaml("new", tier=None)})
        push_branch(repo)
        run(repo, FakeGitHub())
        assert run_git(origin, "rev-parse", "main").strip() == main_before

    def test_nothing_to_do(self, repo, origin):
        repo.commit({rule_path("tiered"): rule_yaml("tiered", tier=ENTERPRISE_ONLY)})
        push_branch(repo)
        github = FakeGitHub()
        assert run(repo, github)[1] is None
        assert run_git(origin, "rev-parse", f"refs/heads/{BRANCH}").strip() == repo.head()
        assert github.dispatches == [] and github.comments == []

    def test_second_run_on_the_bot_commit_does_nothing(self, repo, origin):
        repo.commit({rule_path("new"): rule_yaml("new", tier=None)})
        push_branch(repo)
        _, commit = run(repo, FakeGitHub())
        run_git(repo.path, "reset", "-q", "--hard", commit)
        github = FakeGitHub()
        assert run(repo, github)[1] is None
        assert github.comments == []

    def test_only_the_prs_rules_count_when_main_moved(self, repo, origin):
        repo.commit({rule_path("new"): rule_yaml("new", tier="core")})
        push_branch(repo)
        # main moves on after the branch forked: another no-key rule lands, and the legacy rule changes.
        run_git(repo.path, "switch", "-q", "main")
        repo.commit({rule_path("other"): rule_yaml("other", tier=None), rule_path("legacy"): rule_yaml("legacy", source="x")})
        run_git(repo.path, "push", "-q", "origin", "main")
        run_git(repo.path, "switch", "-q", BRANCH)
        run_git(repo.path, "fetch", "-q", "origin")
        github = FakeGitHub()
        assert run(repo, github)[1] is None
        assert github.comments == []

    def test_branch_moved_means_no_push_and_no_comment(self, repo, origin):
        repo.commit({rule_path("new"): rule_yaml("new", tier=None)})
        push_branch(repo)
        started_at = repo.head()
        # The author pushes again before the bot does.
        repo.commit({rule_path("newer"): rule_yaml("newer")})
        push_branch(repo)
        moved_to = repo.head()
        github = FakeGitHub()

        result, commit = default_tier.add_defaults(str(repo.path), github, "origin/main", started_at, BRANCH, 7)

        assert commit is None and list(result.updates) == [rule_path("new")]
        assert run_git(origin, "rev-parse", f"refs/heads/{BRANCH}").strip() == moved_to
        assert github.dispatches == [] and github.comments == []

    def test_result_passes_tier_check(self, repo, origin):
        base = repo.head()
        repo.commit({rule_path("new"): rule_yaml("new", tier=None)})
        push_branch(repo)
        _, commit = run(repo, FakeGitHub())
        run_git(repo.path, "fetch", "-q", "origin")
        base_files, head_files = read_tree(repo.path, base, RULES_DIR), read_tree(repo.path, commit, RULES_DIR)
        assert check(base_files, head_files, non_core_enabled=True) == []
        assert parse_rule(rule_path("new"), head_files[rule_path("new")].content).id == rule_id("new")

    def test_main_runs_end_to_end(self, repo, origin, monkeypatch, capsys):
        repo.commit({rule_path("new"): rule_yaml("new", tier=None)})
        push_branch(repo)
        github = FakeGitHub()
        monkeypatch.setattr(default_tier, "GhCli", lambda name: github)
        code = default_tier.main(
            ["--repo", str(repo.path), "--base", "origin/main", "--branch", BRANCH, "--github-repo", "o/r", "--pr", "7"]
        )
        assert code == 0
        assert "Added feed_tier: core_with_delay to 1 rule(s)" in capsys.readouterr().out
        assert len(github.comments) == 1
