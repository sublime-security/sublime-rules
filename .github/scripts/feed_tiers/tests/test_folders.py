"""Tiers beyond detection-rules/: automations, exclusions, DLP rules and YARA, plus the always-public folders."""

from datetime import datetime, timedelta, timezone

import pytest

import default_tier
import guard
import promote
import stamp_core
import sync
import tier_check
from gittree import Entry, read_tree
from helpers import Repo, rule_yaml, run_git
from project import ProjectionError, project
from rules import (
    CORE,
    CORE_WITH_DELAY,
    ENTERPRISE_ONLY,
    MANAGED_DIRS,
    RuleError,
    has_tier,
    is_managed,
    parse_rule,
    parse_rules,
    set_tier,
)

YARA = b"rule x\n{\n    condition:\n        true\n}\n"
YAML_FOLDERS = ["automations", "detection-rules", "dlp-rules", "exclusions"]


def yara(tier=None, body=YARA):
    return (f"// feed_tier: {tier}\n".encode() if tier else b"") + body


def entries(files):
    return {p: Entry("100644", c) for p, c in files.items()}


class TestWhichFilesHaveTiers:
    @pytest.mark.parametrize(
        "path, managed, tiered",
        [
            ("detection-rules/a.yml", True, True),
            ("detection-rules/no_extension", True, True),
            ("dlp-rules/a.yml", True, True),
            ("automations/a.yml", True, True),
            ("exclusions/a.yml", True, True),
            ("yara/a.yar", True, True),
            ("yara/sublime_yara_test.zip", True, False),
            ("insights/category/a.yml", True, False),
            ("discovery-rules/a.yml", False, False),
            ("emls/a.eml", False, False),
            ("README.md", False, False),
            (".github/workflows/x.yml", False, False),
        ],
    )
    def test_classification(self, path, managed, tiered):
        assert is_managed(path) is managed
        assert has_tier(path) is tiered

    def test_managed_dirs(self):
        assert MANAGED_DIRS == ("automations", "detection-rules", "dlp-rules", "exclusions", "insights", "yara")


class TestYamlFolders:
    @pytest.mark.parametrize("folder", YAML_FOLDERS)
    @pytest.mark.parametrize("tier", [None, CORE, CORE_WITH_DELAY, ENTERPRISE_ONLY])
    def test_same_tiers_as_detection_rules(self, folder, tier):
        rule = parse_rule(f"{folder}/r.yml", rule_yaml("r", tier=tier, rule_id_=None))
        assert rule.tier == tier
        assert rule.effective_tier == (tier or CORE_WITH_DELAY)

    @pytest.mark.parametrize("folder", YAML_FOLDERS)
    def test_unknown_tier_fails(self, folder):
        with pytest.raises(RuleError, match="must be one of"):
            parse_rule(f"{folder}/r.yml", rule_yaml("r", tier="Core", rule_id_=None))

    def test_duplicate_id_across_folders_fails(self):
        _, errors = parse_rules({"detection-rules/a.yml": rule_yaml("same"), "dlp-rules/b.yml": rule_yaml("same")})
        assert len(errors) == 1 and "is used by more than one rule" in errors[0]


class TestYara:
    P = "yara/x.yar"

    def test_no_line_is_core_with_delay(self):
        rule = parse_rule(self.P, yara())
        assert (rule.tier, rule.effective_tier, rule.is_public) == (None, CORE_WITH_DELAY, False)

    @pytest.mark.parametrize("tier", [CORE, CORE_WITH_DELAY])
    def test_first_line(self, tier):
        assert parse_rule(self.P, yara(tier)).tier == tier

    @pytest.mark.parametrize("line", [b"//feed_tier:core\n", b"//   feed_tier :  core  \n", b"// feed_tier: core\r\n"])
    def test_spacing_and_crlf(self, line):
        assert parse_rule(self.P, line + YARA).tier == CORE

    def test_enterprise_only_is_not_allowed(self):
        with pytest.raises(RuleError, match="for a YARA file, not 'enterprise_only'"):
            parse_rule(self.P, yara(ENTERPRISE_ONLY))

    def test_unknown_tier_fails(self):
        with pytest.raises(RuleError, match="for a YARA file"):
            parse_rule(self.P, yara("Core"))

    @pytest.mark.parametrize(
        "content",
        [
            b"rule x { condition: true }\n// feed_tier: core\n",  # not the first line
            b"\n// feed_tier: core\n" + YARA,  # not the first line either
            yara(CORE) + b"// feed_tier: core\n",  # twice
            b"/* feed_tier: core */\n" + YARA,  # not a line comment
            b"// feed_tier: core # public\n" + YARA,  # extra text
        ],
    )
    def test_anywhere_else_fails(self, content):
        with pytest.raises(RuleError, match="must only appear on the first line"):
            parse_rule(self.P, content)

    def test_not_utf8_fails(self):
        with pytest.raises(RuleError, match="UTF-8"):
            parse_rule(self.P, b"\xff\xfe" + YARA)

    def test_set_tier_adds_the_first_line(self):
        assert set_tier(self.P, YARA, CORE) == b"// feed_tier: core\n" + YARA

    def test_set_tier_replaces_the_first_line(self):
        assert set_tier(self.P, yara(CORE_WITH_DELAY), CORE) == yara(CORE)

    def test_set_tier_keeps_crlf(self):
        body = YARA.replace(b"\n", b"\r\n")
        assert set_tier(self.P, body, CORE) == b"// feed_tier: core\r\n" + body
        assert set_tier(self.P, b"// feed_tier: core_with_delay\r\n" + body, CORE) == b"// feed_tier: core\r\n" + body

    def test_set_tier_refuses_enterprise_only(self):
        with pytest.raises(RuleError, match="can't be enterprise_only"):
            set_tier(self.P, YARA, ENTERPRISE_ONLY)

    def test_non_yar_files_are_always_public(self):
        rule = parse_rule("yara/sublime_yara_test.zip", b"PK\x03\x04\xff\xfe binary")
        assert rule.always_public and rule.is_public and rule.tier_label == "core (always public)"


class TestAlwaysPublic:
    @pytest.mark.parametrize("content", [b"anything: [unclosed\n", b"\xff\xfe", b"feed_tier: enterprise_only\n"])
    def test_insights_are_never_parsed(self, content):
        rule = parse_rule("insights/a/b.yml", content)
        assert rule.always_public and rule.is_public

    def test_set_tier_refuses(self):
        with pytest.raises(RuleError, match="always public"):
            set_tier("insights/a.yml", b"name: x\n", CORE)


PRIVATE = {
    "detection-rules/core.yml": rule_yaml("d-core", tier=CORE),
    "detection-rules/ent.yml": rule_yaml("d-ent", tier=ENTERPRISE_ONLY),
    "dlp-rules/core.yml": rule_yaml("dlp-core", tier=CORE),
    "dlp-rules/delayed.yml": rule_yaml("dlp-delayed", tier=CORE_WITH_DELAY),
    "automations/core.yml": rule_yaml("a-core", tier=CORE, rule_id_=None),
    "automations/nokey.yml": rule_yaml("a-nokey", tier=None, rule_id_=None),
    "exclusions/core.yml": rule_yaml("e-core", tier=CORE, rule_id_=None),
    "exclusions/ent.yml": rule_yaml("e-ent", tier=ENTERPRISE_ONLY, rule_id_=None),
    "yara/core.yar": yara(CORE),
    "yara/delayed.yar": yara(CORE_WITH_DELAY),
    "yara/nokey.yar": yara(),
    "yara/sublime_yara_test.zip": b"PK\x03\x04 binary",
    "insights/category/q.yml": b"name: q\ntype: query\nsource: |\n  1\n",
}
PUBLIC = {
    "detection-rules/core.yml",
    "dlp-rules/core.yml",
    "automations/core.yml",
    "exclusions/core.yml",
    "yara/core.yar",
    "yara/sublime_yara_test.zip",
    "insights/category/q.yml",
}


class TestProjection:
    def test_each_folder(self):
        plan = project(entries(PRIVATE), {})
        assert set(plan.desired) == PUBLIC
        assert plan.desired == {p: Entry("100644", PRIVATE[p]) for p in PUBLIC}

    def test_always_public_files_are_removed_when_deleted(self):
        public = entries({p: PRIVATE[p] for p in PUBLIC})
        private = {p: c for p, c in PRIVATE.items() if not p.startswith("insights/")}
        assert project(entries(private), public).removed == ["insights/category/q.yml"]

    @pytest.mark.parametrize(
        "path, demoted",
        [
            ("automations/core.yml", rule_yaml("a-core", tier=ENTERPRISE_ONLY, rule_id_=None)),
            ("exclusions/core.yml", rule_yaml("e-core", tier=None, rule_id_=None)),
            ("dlp-rules/core.yml", rule_yaml("dlp-core", tier=CORE_WITH_DELAY)),
            ("yara/core.yar", yara(CORE_WITH_DELAY)),
            ("yara/core.yar", yara()),
        ],
    )
    def test_demotion_fails_in_every_folder(self, path, demoted):
        public = entries({p: PRIVATE[p] for p in PUBLIC})
        with pytest.raises(ProjectionError, match="Rules are never demoted"):
            project(entries({**PRIVATE, path: demoted}), public)

    def test_bad_yara_tier_fails_the_whole_sync(self):
        with pytest.raises(ProjectionError, match="yara/bad.yar"):
            project(entries({**PRIVATE, "yara/bad.yar": yara(ENTERPRISE_ONLY)}), {})


class TestTierCheck:
    BASE = {p: PRIVATE[p] for p in PUBLIC}

    def check(self, head, enabled=True):
        return tier_check.check(entries(self.BASE), entries({**self.BASE, **head}), enabled)

    @pytest.mark.parametrize("folder", ["automations", "exclusions", "dlp-rules"])
    @pytest.mark.parametrize("tier", [None, CORE, CORE_WITH_DELAY, ENTERPRISE_ONLY])
    def test_new_yaml_rule_any_tier(self, folder, tier):
        assert self.check({f"{folder}/new.yml": rule_yaml(f"{folder}-new", tier=tier, rule_id_=None)}) == []

    @pytest.mark.parametrize("tier", [None, CORE, CORE_WITH_DELAY])
    def test_new_yara_core_or_delayed(self, tier):
        assert self.check({"yara/new.yar": yara(tier)}) == []

    def test_new_yara_enterprise_only_fails(self):
        [(path, problem)] = self.check({"yara/new.yar": yara(ENTERPRISE_ONLY)})
        assert path == "yara/new.yar" and "for a YARA file, not 'enterprise_only'" in problem

    def test_gate_applies_to_every_folder(self):
        head = {
            "automations/new.yml": rule_yaml("a-new", tier=None, rule_id_=None),
            "yara/new.yar": yara(CORE_WITH_DELAY),
            "exclusions/core2.yml": rule_yaml("e-core2", tier=CORE, rule_id_=None),
        }
        assert [p for p, _ in self.check(head, enabled=False)] == ["automations/new.yml", "yara/new.yar"]

    def test_always_public_files_pass_even_with_the_gate_off(self):
        head = {"insights/new.yml": b"anything\n", "yara/other.zip": b"\x00"}
        assert self.check(head, enabled=False) == []

    @pytest.mark.parametrize(
        "path, content",
        [
            ("automations/core.yml", rule_yaml("a-core", tier=ENTERPRISE_ONLY, rule_id_=None)),
            ("yara/core.yar", YARA),  # removing the line
        ],
    )
    def test_demotion_fails(self, path, content):
        [(got, problem)] = self.check({path: content})
        assert got == path and "Rules are never demoted" in problem


@pytest.fixture
def stamp_repo(tmp_path):
    r = Repo(tmp_path / "r")
    r.commit(
        {
            "automations/a.yml": rule_yaml("a", tier=None, rule_id_=None),
            "exclusions/e.yml": rule_yaml("e", tier=None, rule_id_=None),
            "dlp-rules/d.yml": rule_yaml("d", tier=None),
            "yara/y.yar": YARA,
            "yara/t.zip": b"PK binary",
            "insights/q.yml": b"name: q\n",
            "discovery-rules/x.yml": rule_yaml("x", tier=None),
        }
    )
    return r


class TestRealShapes:
    def test_automation_ending_in_source_with_no_final_newline(self):
        # automations/remediate_messages_via_herd_immunity.yml today.
        content = (
            b'name: "Remediate"\ntype: "triage_rule"\ntriage_abuse_reports: true\n'
            b'default_actions: ["quarantine_message"]\nsource: |\n  type.inbound\n  and triage.user_reports.count > 5'
        )
        stamped = set_tier("automations/r.yml", content, CORE)
        assert stamped == content.replace(b"source: |", b"feed_tier: core\nsource: |")

    def test_automation_with_plain_source_and_no_final_newline(self):
        # automations/acknowledge_user_report.yml today.
        content = b'name: "Ack"\ntype: "triage_rule"\nsource: true'
        assert set_tier("automations/a.yml", content, CORE) == b'name: "Ack"\ntype: "triage_rule"\nfeed_tier: core\nsource: true'


class TestStamp:
    def test_every_tiered_folder(self, stamp_repo):
        stamped = stamp_core.stamp(stamp_repo.path)
        assert stamped == ["automations/a.yml", "dlp-rules/d.yml", "exclusions/e.yml", "yara/y.yar"]
        assert (stamp_repo.path / "yara/y.yar").read_bytes() == yara(CORE)
        automation = rule_yaml("a", tier=None, rule_id_=None).replace(b"source: |", b"feed_tier: core\nsource: |")
        assert (stamp_repo.path / "automations/a.yml").read_bytes() == automation
        for untouched in ("yara/t.zip", "insights/q.yml", "discovery-rules/x.yml"):
            assert (stamp_repo.path / untouched).read_bytes() == stamp_repo.read(untouched)


@pytest.fixture
def repos(tmp_path):
    private = Repo(tmp_path / "private")
    private.commit({"README.md": "x\n"})
    public_path = tmp_path / "public"
    run_git(tmp_path, "clone", "-q", str(private.path), str(public_path))
    run_git(public_path, "config", "user.name", "Mirror")
    run_git(public_path, "config", "user.email", "mirror@example.com")
    public = Repo.__new__(Repo)
    public.path = public_path
    return private, public


class TestSyncAndGuard:
    def test_syncs_each_folder_and_the_guard_passes(self, repos):
        private, public = repos
        private.commit(PRIVATE)
        result = sync.sync(str(private.path), str(public.path))
        assert result.commit is not None
        tree = read_tree(public.path, "HEAD", MANAGED_DIRS)
        assert {p: e.content for p, e in tree.items()} == {p: PRIVATE[p] for p in PUBLIC}
        assert guard.main(["--repo", str(public.path)]) == 0

    @pytest.mark.parametrize(
        "path, content",
        [
            ("automations/leak.yml", rule_yaml("leak", tier=ENTERPRISE_ONLY, rule_id_=None)),
            ("exclusions/leak.yml", rule_yaml("leak", tier=None, rule_id_=None)),
            ("dlp-rules/leak.yml", rule_yaml("leak", tier=CORE_WITH_DELAY)),
            ("yara/leak.yar", yara(CORE_WITH_DELAY)),
            ("yara/leak.yar", YARA),
        ],
    )
    def test_guard_catches_a_leak_in_any_folder(self, repos, path, content):
        _, public = repos
        public.commit({path: content})
        assert guard.main(["--repo", str(public.path)]) == 1

    def test_guard_ignores_unmanaged_folders(self, repos):
        _, public = repos
        public.commit({"discovery-rules/x.yml": rule_yaml("x", tier=ENTERPRISE_ONLY)})
        assert guard.main(["--repo", str(public.path)]) == 0


class FakeGitHub:
    def __init__(self):
        self.prs, self.dispatches, self.comments = [], [], []

    def find_open_pr(self, branch):
        return None

    def create_pr(self, *, branch, base, title, body, label):
        self.prs.append(dict(branch=branch, title=title, body=body))
        return f"https://github.example/pr/{len(self.prs)}"

    def dispatch_workflow(self, workflow, ref):
        self.dispatches.append((workflow, ref))

    def comment_pr(self, number, body):
        self.comments.append((number, body))


class TestPromote:
    def test_yara_and_automation_are_promoted(self, tmp_path):
        origin = tmp_path / "origin.git"
        run_git(tmp_path, "init", "-q", "--bare", "-b", "main", str(origin))
        repo = Repo(tmp_path / "work")
        t0 = datetime(2027, 1, 1, tzinfo=timezone.utc)
        repo.commit(
            {
                "yara/y.yar": yara(CORE_WITH_DELAY),
                "automations/a.yml": rule_yaml("a", tier=None, rule_id_=None),
                "insights/q.yml": b"name: q\n",
            },
            when=t0,
        )
        run_git(repo.path, "remote", "add", "origin", str(origin))
        github = FakeGitHub()
        report = promote.promote(str(repo.path), github, t0 + timedelta(days=91))
        assert report.errors == []
        branches = {pr["branch"] for pr in github.prs}
        assert branches == {"auto/promote-core/yara-y", "auto/promote-core/automations-a"}
        yara_branch = run_git(origin, "show", "auto/promote-core/yara-y:yara/y.yar").encode()
        assert yara_branch == yara(CORE)


class TestDefaultTier:
    def test_each_folder(self):
        head = entries(
            {
                "automations/a.yml": rule_yaml("a", tier=None, rule_id_=None),
                "yara/y.yar": YARA,
                "yara/t.zip": b"PK",
                "insights/q.yml": b"name: q\n",
                "exclusions/e.yml": rule_yaml("e", tier=CORE, rule_id_=None),
            }
        )
        result = default_tier.missing_tiers({}, head)
        assert sorted(result.updates) == ["automations/a.yml", "yara/y.yar"]
        assert result.updates["yara/y.yar"].content == yara(CORE_WITH_DELAY)
        assert result.skipped == []
