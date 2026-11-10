"""gitdates.py and promote.py against real git repos, with an in-memory GitHub."""

from datetime import datetime, timedelta, timezone

import pytest

import promote
from gitdates import DateError, first_merged
from helpers import Repo, rule_id, rule_path, rule_yaml, run_git
from rules import CORE, CORE_WITH_DELAY, ENTERPRISE_ONLY, parse_rule

T0 = datetime(2027, 1, 1, 12, 0, tzinfo=timezone.utc)
DAY = timedelta(days=1)


def day(n: float) -> datetime:
    return T0 + n * DAY


class FakeGitHub:
    def __init__(self):
        self.prs: list[dict] = []
        self.dispatches: list[tuple[str, str]] = []
        self.fail_create = False

    def find_open_pr(self, branch):
        for pr in self.prs:
            if pr["branch"] == branch and pr["state"] == "open":
                return pr["url"]
        return None

    def create_pr(self, *, branch, base, title, body, label):
        if self.fail_create:
            raise promote.GitHubError("boom")
        url = f"https://github.example/pr/{len(self.prs) + 1}"
        self.prs.append(dict(branch=branch, base=base, title=title, body=body, label=label, url=url, state="open"))
        return url

    def dispatch_workflow(self, workflow, ref):
        self.dispatches.append((workflow, ref))


@pytest.fixture
def origin(tmp_path):
    path = tmp_path / "origin.git"
    run_git(tmp_path, "init", "-q", "--bare", "-b", "main", str(path))
    return path


@pytest.fixture
def repo(tmp_path, origin):
    r = Repo(tmp_path / "work", name="github-actions[bot]", email="bot@example.com")
    r.commit({rule_path("legacy"): rule_yaml("legacy")}, when=day(-500))
    run_git(r.path, "remote", "add", "origin", str(origin))
    run_git(r.path, "push", "-q", "origin", "main")
    return r


class TestFirstMerged:
    def test_add_date(self, repo):
        repo.commit({rule_path("d"): rule_yaml("d", tier=CORE_WITH_DELAY)}, when=day(0))
        repo.commit({rule_path("d"): rule_yaml("d", tier=CORE_WITH_DELAY, source="edited")}, when=day(10))
        assert first_merged(str(repo.path), rule_path("d"), rule_id("d")) == day(0)

    def test_committer_date_not_author_date(self, repo):
        run_git(repo.path, "config", "user.name", "x")
        (repo.path / rule_path("d")).write_bytes(rule_yaml("d", tier=CORE_WITH_DELAY))
        run_git(repo.path, "add", "-A")
        run_git(
            repo.path, "commit", "-q", "-m", "squash",
            env={"GIT_AUTHOR_DATE": "2020-01-01T00:00:00+00:00", "GIT_COMMITTER_DATE": day(5).isoformat()},
        )
        assert first_merged(str(repo.path), rule_path("d"), rule_id("d")) == day(5)

    def test_follows_renames(self, repo):  # S9
        repo.commit({rule_path("d"): rule_yaml("d", tier=CORE_WITH_DELAY)}, when=day(0))
        repo.rename(rule_path("d"), "detection-rules/renamed.yml", when=day(50))
        assert first_merged(str(repo.path), "detection-rules/renamed.yml", rule_id("d")) == day(0)

    def test_tier_change_keeps_the_clock(self, repo):  # S18
        repo.commit({rule_path("d"): rule_yaml("d", tier=ENTERPRISE_ONLY)}, when=day(-200))
        repo.commit({rule_path("d"): rule_yaml("d", tier=CORE_WITH_DELAY)}, when=day(0))
        assert first_merged(str(repo.path), rule_path("d"), rule_id("d")) == day(-200)

    def test_similar_rule_is_not_its_ancestor(self, repo):
        # git log --follow calls this a copy or rename of the older rule; the id doesn't.
        repo.commit({rule_path("old"): rule_yaml("old", tier=ENTERPRISE_ONLY, rule_id_="old-id")}, when=day(-300))
        repo.commit(
            {rule_path("old"): None, rule_path("new"): rule_yaml("old", tier=CORE_WITH_DELAY, rule_id_="new-id")},
            when=day(0),
        )
        follow = run_git(repo.path, "log", "--follow", "--diff-filter=A", "--format=%cI", "--", rule_path("new")).split()
        assert datetime.fromisoformat(follow[-1]) < day(0)  # what --follow would have said
        assert first_merged(str(repo.path), rule_path("new"), "new-id") == day(0)

    def test_new_rule_is_not_a_copy_of_an_existing_one(self, repo):
        repo.commit({"detection-rules/noid": rule_yaml("noid", tier=CORE_WITH_DELAY, rule_id_=None)}, when=day(3))
        repo.commit({rule_path("d"): rule_yaml("legacy", tier=CORE_WITH_DELAY, rule_id_="d-id")}, when=day(4))
        assert first_merged(str(repo.path), "detection-rules/noid", None) == day(3)
        assert first_merged(str(repo.path), rule_path("d"), "d-id") == day(4)

    @pytest.mark.parametrize(
        "mention",
        [
            "# id: \"later-id\"\n",
            "related_detections:\n  - id: \"later-id\"\n",
            "notes: \"id: later-id\"\n",
            "old_id: \"later-id\"\n",
        ],
    )
    def test_id_mentioned_earlier_does_not_count(self, repo, mention):
        repo.commit({rule_path("other"): rule_yaml("other", extra=mention)}, when=day(-300))
        repo.commit({rule_path("d"): rule_yaml("d", tier=CORE_WITH_DELAY, rule_id_="later-id")}, when=day(0))
        assert first_merged(str(repo.path), rule_path("d"), "later-id") == day(0)

    def test_id_inside_source_does_not_count(self, repo):
        repo.commit({rule_path("other"): rule_yaml("other", source='type.inbound\nid: "later-id"')}, when=day(-300))
        repo.commit({rule_path("d"): rule_yaml("d", tier=CORE_WITH_DELAY, rule_id_="later-id")}, when=day(0))
        assert first_merged(str(repo.path), rule_path("d"), "later-id") == day(0)

    @pytest.mark.parametrize("line", ['id: "x-1"', "id: 'x-1'", "id: x-1", 'id:   "x-1"   ', 'id: "x-1"  # generated'])
    def test_id_line_styles(self, repo, line):
        content = rule_yaml("d", tier=CORE_WITH_DELAY, rule_id_=None) + line.encode() + b"\n"
        repo.commit({rule_path("d"): content}, when=day(0))
        assert first_merged(str(repo.path), rule_path("d"), "x-1") == day(0)

    def test_crlf(self, repo):
        repo.commit({rule_path("d"): rule_yaml("d", tier=CORE_WITH_DELAY).replace(b"\n", b"\r\n")}, when=day(0))
        assert first_merged(str(repo.path), rule_path("d"), rule_id("d")) == day(0)

    def test_id_with_regex_characters(self, repo):
        repo.commit({rule_path("x"): rule_yaml("x", rule_id_="a.b")}, when=day(-10))  # "." would match "a-b"... and "a.b"
        repo.commit({rule_path("d"): rule_yaml("d", tier=CORE_WITH_DELAY, rule_id_="a-b")}, when=day(0))
        assert first_merged(str(repo.path), rule_path("d"), "a-b") == day(0)
        repo.commit({rule_path("e"): rule_yaml("e", tier=CORE_WITH_DELAY, rule_id_="a+b")}, when=day(1))
        assert first_merged(str(repo.path), rule_path("e"), "a+b") == day(1)

    def test_heavy_rewrite_and_rename_keeps_the_clock(self, repo):
        repo.commit({rule_path("d"): rule_yaml("d", tier=CORE_WITH_DELAY)}, when=day(0))
        repo.rename(
            rule_path("d"),
            "detection-rules/rewritten.yml",
            when=day(40),
            content=rule_yaml("totally different", tier=CORE_WITH_DELAY, rule_id_=rule_id("d"), source="x\n" * 40),
        )
        assert first_merged(str(repo.path), "detection-rules/rewritten.yml", rule_id("d")) == day(0)

    def test_new_id_restarts_the_clock(self, repo):
        repo.commit({rule_path("d"): rule_yaml("d", tier=CORE_WITH_DELAY, rule_id_="first")}, when=day(0))
        repo.commit({rule_path("d"): rule_yaml("d", tier=CORE_WITH_DELAY, rule_id_="second")}, when=day(30))
        assert first_merged(str(repo.path), rule_path("d"), "second") == day(30)

    def test_rule_without_id_restarts_on_rename(self, repo):
        repo.commit({"detection-rules/noid": rule_yaml("noid", tier=CORE_WITH_DELAY, rule_id_=None)}, when=day(0))
        repo.rename("detection-rules/noid", "detection-rules/noid2", when=day(30))
        assert first_merged(str(repo.path), "detection-rules/noid2", None) == day(30)

    def test_id_outside_detection_rules_does_not_count(self, repo):
        repo.commit({"discovery-rules/x.yml": rule_yaml("x", rule_id_="shared")}, when=day(-100))
        repo.commit({rule_path("d"): rule_yaml("d", tier=CORE_WITH_DELAY, rule_id_="shared")}, when=day(0))
        assert first_merged(str(repo.path), rule_path("d"), "shared") == day(0)

    def test_deleted_and_re_added_counts_from_first_add(self, repo):
        repo.commit({rule_path("d"): rule_yaml("d", tier=CORE_WITH_DELAY)}, when=day(0))
        repo.commit({rule_path("d"): None}, when=day(5))
        repo.commit({rule_path("d"): rule_yaml("d", tier=CORE_WITH_DELAY)}, when=day(20))
        assert first_merged(str(repo.path), rule_path("d"), rule_id("d")) == day(0)

    def test_without_id(self, repo):
        repo.commit({"detection-rules/noid": rule_yaml("noid", tier=CORE_WITH_DELAY, rule_id_=None)}, when=day(3))
        assert first_merged(str(repo.path), "detection-rules/noid", None) == day(3)

    def test_missing(self, repo):
        with pytest.raises(DateError):
            first_merged(str(repo.path), rule_path("nope"), "nope-id")
        with pytest.raises(DateError):
            first_merged(str(repo.path), rule_path("nope"), None)


class TestPromote:
    def run(self, repo, github, now, **kwargs):
        return promote.promote(str(repo.path), github, now, **kwargs)

    @pytest.mark.parametrize(
        "age, due",
        [
            (timedelta(days=89, hours=23, minutes=59), False),
            (timedelta(days=90), True),
            (timedelta(days=90, seconds=1), True),
            (timedelta(days=1000), True),
        ],
    )
    def test_boundary(self, repo, age, due):  # S4, S5
        repo.commit({rule_path("d"): rule_yaml("d", tier=CORE_WITH_DELAY)}, when=day(0))
        github = FakeGitHub()
        report = self.run(repo, github, day(0) + age)
        assert len(github.prs) == (1 if due else 0)
        assert len(report.waiting) == (0 if due else 1)

    def test_timezones(self, repo):
        repo.commit({rule_path("d"): rule_yaml("d", tier=CORE_WITH_DELAY)}, when=day(0))
        tokyo = timezone(timedelta(hours=9))
        github = FakeGitHub()
        self.run(repo, github, (day(90) - timedelta(seconds=1)).astimezone(tokyo))
        assert github.prs == []
        self.run(repo, github, day(90).astimezone(tokyo))
        assert len(github.prs) == 1

    def test_opens_one_line_pr_and_dispatches_validation(self, repo, origin):
        content = rule_yaml("Delayed rule", tier=CORE_WITH_DELAY, source="type.inbound\nand 1 == 1")
        repo.commit({rule_path("d"): content}, when=day(0))
        run_git(repo.path, "push", "-q", "origin", "main")
        github = FakeGitHub()
        report = self.run(repo, github, day(91))

        branch = f"auto/promote-core/{rule_id('Delayed rule')}"
        assert [(c.rule.path, url) for c, url in report.opened] == [(rule_path("d"), "https://github.example/pr/1")]
        pr = github.prs[0]
        assert (pr["branch"], pr["base"], pr["label"], pr["title"]) == (branch, "main", "auto-promote", "Promote Delayed rule to core")
        assert "enterprise_only" in pr["body"] and "2027-01-01" in pr["body"]
        assert github.dispatches == [("rule-validate.yml", branch), ("tier-check.yml", branch)]

        pushed = run_git(origin, "rev-parse", f"refs/heads/{branch}").strip()
        assert run_git(origin, "rev-parse", f"{pushed}^").strip() == repo.head()
        diff = run_git(origin, "diff", "--name-only", f"{pushed}^", pushed).split()
        assert diff == [rule_path("d")]
        promoted = run_git(origin, "show", f"{pushed}:{rule_path('d')}").encode()
        assert promoted == content.replace(b"feed_tier: core_with_delay", b"feed_tier: core")
        assert parse_rule(rule_path("d"), promoted).tier == CORE
        assert run_git(origin, "log", "-1", "--format=%an", pushed).strip() == "github-actions[bot]"

    def test_main_is_not_touched(self, repo, origin):
        repo.commit({rule_path("d"): rule_yaml("d", tier=CORE_WITH_DELAY)}, when=day(0))
        run_git(repo.path, "push", "-q", "origin", "main")
        main_before = run_git(origin, "rev-parse", "main").strip()
        local_before = repo.head()
        self.run(repo, FakeGitHub(), day(100))
        assert run_git(origin, "rev-parse", "main").strip() == main_before
        assert repo.head() == local_before

    def test_open_pr_is_not_duplicated(self, repo):  # S6
        repo.commit({rule_path("d"): rule_yaml("d", tier=CORE_WITH_DELAY)}, when=day(0))
        github = FakeGitHub()
        self.run(repo, github, day(90))
        report = self.run(repo, github, day(91))
        assert len(github.prs) == 1 and len(report.already_open) == 1
        assert len(github.dispatches) == 2

    def test_closed_pr_is_reopened(self, repo):
        repo.commit({rule_path("d"): rule_yaml("d", tier=CORE_WITH_DELAY)}, when=day(0))
        github = FakeGitHub()
        self.run(repo, github, day(90))
        github.prs[0]["state"] = "closed"
        self.run(repo, github, day(91))
        assert [pr["state"] for pr in github.prs] == ["closed", "open"]

    def test_stale_branch_is_replaced(self, repo, origin):
        repo.commit({rule_path("d"): rule_yaml("d", tier=CORE_WITH_DELAY)}, when=day(0))
        github = FakeGitHub()
        self.run(repo, github, day(90))
        github.prs[0]["state"] = "closed"
        repo.commit({rule_path("other"): rule_yaml("other")}, when=day(95))
        self.run(repo, github, day(96))
        branch = github.prs[1]["branch"]
        assert run_git(origin, "rev-parse", f"{branch}^").strip() == repo.head()

    @pytest.mark.parametrize("tier", [CORE, ENTERPRISE_ONLY, None])
    def test_only_core_with_delay(self, repo, tier):
        repo.commit({rule_path("r"): rule_yaml("r", tier=tier)}, when=day(0))
        github = FakeGitHub()
        report = self.run(repo, github, day(1000))
        assert github.prs == [] and report.waiting == []

    def test_promoted_by_hand_is_left_alone(self, repo):  # S7
        repo.commit({rule_path("d"): rule_yaml("d", tier=CORE_WITH_DELAY)}, when=day(0))
        repo.commit({rule_path("d"): rule_yaml("d", tier=CORE)}, when=day(3))
        github = FakeGitHub()
        self.run(repo, github, day(200))
        assert github.prs == []

    def test_renamed_rule_keeps_its_clock(self, repo):  # S9
        repo.commit({rule_path("d"): rule_yaml("d", tier=CORE_WITH_DELAY)}, when=day(0))
        repo.rename(rule_path("d"), "detection-rules/renamed.yml", when=day(50))
        github = FakeGitHub()
        self.run(repo, github, day(89))
        assert github.prs == []
        self.run(repo, github, day(90))
        assert len(github.prs) == 1

    def test_was_enterprise_only_first(self, repo):  # S18
        repo.commit({rule_path("d"): rule_yaml("d", tier=ENTERPRISE_ONLY)}, when=day(-200))
        repo.commit({rule_path("d"): rule_yaml("d", tier=CORE_WITH_DELAY)}, when=day(0))
        github = FakeGitHub()
        self.run(repo, github, day(1))
        assert len(github.prs) == 1

    def test_dry_run(self, repo, origin):
        repo.commit({rule_path("d"): rule_yaml("d", tier=CORE_WITH_DELAY)}, when=day(0))
        github = FakeGitHub()
        report = self.run(repo, github, day(100), dry_run=True)
        assert [c.rule.path for c in report.would_open] == [rule_path("d")]
        assert github.prs == [] and github.dispatches == []
        assert run_git(origin, "for-each-ref", "refs/heads/auto").strip() == ""

    def test_one_failure_does_not_stop_others(self, repo):
        repo.commit(
            {rule_path("a"): rule_yaml("a", tier=CORE_WITH_DELAY), rule_path("b"): rule_yaml("b", tier=CORE_WITH_DELAY)},
            when=day(0),
        )
        github = FakeGitHub()
        calls = []
        original = github.create_pr

        def flaky(**kwargs):
            calls.append(kwargs["branch"])
            if len(calls) == 1:
                raise promote.GitHubError("rate limited")
            return original(**kwargs)

        github.create_pr = flaky
        report = self.run(repo, github, day(90))
        assert len(report.errors) == 1 and len(report.opened) == 1

    def test_broken_rule_elsewhere_is_reported_but_does_not_block(self, repo):
        repo.commit({rule_path("d"): rule_yaml("d", tier=CORE_WITH_DELAY), rule_path("bad"): b"feed_tier: x\n"}, when=day(0))
        github = FakeGitHub()
        report = self.run(repo, github, day(90))
        assert len(github.prs) == 1 and len(report.errors) == 1

    def test_custom_delay(self, repo):
        repo.commit({rule_path("d"): rule_yaml("d", tier=CORE_WITH_DELAY)}, when=day(0))
        github = FakeGitHub()
        self.run(repo, github, day(7), delay=timedelta(days=7))
        assert len(github.prs) == 1

    def test_rule_without_id_gets_a_path_branch(self, repo):
        repo.commit({"detection-rules/no id here": rule_yaml("x", tier=CORE_WITH_DELAY, rule_id_=None)}, when=day(0))
        github = FakeGitHub()
        self.run(repo, github, day(90))
        assert github.prs[0]["branch"] == "auto/promote-core/no-id-here"


class TestCli:
    def test_as_of(self):
        assert promote.parse_as_of("2027-04-01") == datetime(2027, 4, 1, tzinfo=timezone.utc)
        assert promote.parse_as_of("2027-04-01T10:00:00+02:00") == datetime(2027, 4, 1, 8, tzinfo=timezone.utc)
        assert abs(promote.parse_as_of("") - datetime.now(timezone.utc)) < timedelta(minutes=1)

    def test_exit_code_on_errors(self, repo, monkeypatch):
        repo.commit({rule_path("bad"): b"feed_tier: x\n"}, when=day(0))
        monkeypatch.setattr(promote, "GhCli", lambda repo: FakeGitHub())
        assert promote.main(["--repo", str(repo.path), "--github-repo", "o/r"]) == 1

    def test_exit_code_ok(self, repo, monkeypatch):
        repo.commit({rule_path("d"): rule_yaml("d", tier=CORE_WITH_DELAY)}, when=day(0))
        monkeypatch.setattr(promote, "GhCli", lambda repo: FakeGitHub())
        assert promote.main(["--repo", str(repo.path), "--github-repo", "o/r", "--as-of", "2027-01-02"]) == 0
