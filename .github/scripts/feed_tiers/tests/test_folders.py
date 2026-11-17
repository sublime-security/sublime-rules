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
    parse_file,
    parse_rule,
    parse_rules,
    public_content,
    set_tier,
)

YARA = b'rule x\n{\n    meta:\n        author = "a"\n    condition:\n        true\n}\n'
YAML_FOLDERS = ["automations", "detection-rules", "dlp-rules", "exclusions"]


def yara(tier=None, name="x"):
    """YARA, with feed_tier as its last meta entry, where set_tier puts it."""
    content = YARA.replace(b"rule x\n", f"rule {name}\n".encode())
    if tier is None:
        return content
    return content.replace(b'author = "a"\n', f'author = "a"\n        feed_tier = "{tier}"\n'.encode())


TWO_RULES = (
    b'rule a\n{\n\tmeta:\n\t\tauthor = "x"\n\t\tdate = "2026-01-01"\n\n\tstrings:\n\t\t$s = "a"\n\tcondition:\n\t\t$s\n}\n'
    b"\n"
    b"rule b : tag1\n{\n    strings:\n        $s = { 50 4b }\n    condition:\n        $s at 0\n}\n"
)


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

    def test_no_key_is_core_with_delay(self):
        rule = parse_rule(self.P, YARA)
        assert (rule.tier, rule.effective_tier, rule.is_public) == (None, CORE_WITH_DELAY, False)

    @pytest.mark.parametrize("tier", [CORE, CORE_WITH_DELAY, ENTERPRISE_ONLY])
    def test_meta(self, tier):
        rule = parse_rule(self.P, yara(tier))
        assert rule.tier == tier and rule.is_public is (tier == CORE)

    def test_every_rule_agreeing(self):
        both = set_tier(self.P, TWO_RULES, CORE)
        assert [r.tier for r in parse_file(self.P, both)] == [CORE, CORE]
        assert public_content(self.P, both) == both

    def test_each_rule_has_its_own_tier(self):
        one = TWO_RULES.replace(b'\t\tdate = "2026-01-01"\n', b'\t\tdate = "2026-01-01"\n\t\tfeed_tier = "core"\n')
        rules = parse_file(self.P, one)
        assert [(r.yara_name, r.tier, r.is_public) for r in rules] == [("a", CORE, True), ("b", None, False)]
        assert rules[0].label == "YARA rule a (yara/x.yar)"
        with pytest.raises(RuleError, match="has 2 YARA rules, not one"):
            parse_rule(self.P, one)

    @pytest.mark.parametrize("value", ['"Core"', '"enterprise"', '""', "true", "1"])
    def test_unknown_tier_fails(self, value):
        content = YARA.replace(b'author = "a"\n', f'author = "a"\n        feed_tier = {value}\n'.encode())
        with pytest.raises(RuleError, match="must be one of core, core_with_delay, enterprise_only"):
            parse_rule(self.P, content)

    def test_twice_in_one_rule_fails(self):
        content = yara(CORE).replace(b'feed_tier = "core"\n', b'feed_tier = "core"\n        feed_tier = "core"\n')
        with pytest.raises(RuleError, match="more than one feed_tier"):
            parse_rule(self.P, content)

    @pytest.mark.parametrize(
        "content",
        [
            b"// feed_tier: core\n" + YARA,  # a comment isn't meta
            YARA.replace(b"    condition:", b'    strings:\n        $feed_tier = "core"\n    condition:\n        $feed_tier or'),
        ],
    )
    def test_feed_tier_outside_meta_is_ignored(self, content):
        assert parse_rule(self.P, content).tier is None

    @pytest.mark.parametrize("content", [b"rule x { condition: }", b"not yara at all {", b""])
    def test_invalid_or_empty_fails(self, content):
        with pytest.raises(RuleError, match="is not valid YARA|has no YARA rules"):
            parse_rule(self.P, content)

    def test_not_utf8_fails(self):
        with pytest.raises(RuleError, match="UTF-8"):
            parse_rule(self.P, b"\xff\xfe" + YARA)

    @pytest.mark.parametrize("tier", [CORE, CORE_WITH_DELAY, ENTERPRISE_ONLY])
    def test_set_tier_adds_it_last_in_meta(self, tier):
        assert set_tier(self.P, YARA, tier) == yara(tier)

    @pytest.mark.parametrize("tier", [CORE, CORE_WITH_DELAY, ENTERPRISE_ONLY])
    def test_set_tier_replaces_the_value(self, tier):
        assert set_tier(self.P, yara(CORE_WITH_DELAY), tier) == yara(tier)

    def test_set_tier_every_rule_with_its_own_indentation_and_a_new_meta_section(self):
        expected = (
            b'rule a\n{\n\tmeta:\n\t\tauthor = "x"\n\t\tdate = "2026-01-01"\n\t\tfeed_tier = "core"\n\n\tstrings:\n'
            b'\t\t$s = "a"\n\tcondition:\n\t\t$s\n}\n'
            b"\n"
            b'rule b : tag1\n{\n    meta:\n        feed_tier = "core"\n    strings:\n        $s = { 50 4b }\n'
            b"    condition:\n        $s at 0\n}\n"
        )
        assert set_tier(self.P, TWO_RULES, CORE) == expected

    def test_set_tier_keeps_crlf(self):
        crlf = TWO_RULES.replace(b"\n", b"\r\n")
        stamped = set_tier(self.P, crlf, CORE)
        assert b"\n" not in stamped.replace(b"\r\n", b"")
        assert stamped == set_tier(self.P, TWO_RULES, CORE).replace(b"\n", b"\r\n")

    def test_set_tier_with_meta_on_the_rule_line_fails_safely(self):
        content = b'rule x { meta: author = "a" condition: true }\n'
        with pytest.raises(RuleError, match="can't find the meta: line"):
            set_tier(self.P, content, CORE)

    def test_set_tier_on_a_one_line_rule_fails_safely(self):
        with pytest.raises(RuleError, match="can't find where to add meta"):
            set_tier(self.P, b"rule x { condition: true }\n", CORE)

    def test_set_tier_leaves_comments_and_imports(self):
        content = b'import "pe"\n// header\n/* block\n   comment */\n' + YARA
        assert set_tier(self.P, content, CORE) == b'import "pe"\n// header\n/* block\n   comment */\n' + yara(CORE)

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
    "yara/core.yar": yara(CORE, "y_core"),
    "yara/delayed.yar": yara(CORE_WITH_DELAY, "y_delayed"),
    "yara/ent.yar": yara(ENTERPRISE_ONLY, "y_ent"),
    "yara/nokey.yar": yara(None, "y_nokey"),
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
            ("yara/core.yar", yara(CORE_WITH_DELAY, "y_core")),
            ("yara/core.yar", yara(ENTERPRISE_ONLY, "y_core")),
            ("yara/core.yar", yara(None, "y_core")),
        ],
    )
    def test_demotion_fails_in_every_folder(self, path, demoted):
        public = entries({p: PRIVATE[p] for p in PUBLIC})
        with pytest.raises(ProjectionError, match="Rules are never demoted"):
            project(entries({**PRIVATE, path: demoted}), public)

    def test_bad_yara_tier_fails_the_whole_sync(self):
        with pytest.raises(ProjectionError, match="yara/bad.yar"):
            project(entries({**PRIVATE, "yara/bad.yar": yara("Core", "y_bad")}), {})


class TestTierCheck:
    BASE = {p: PRIVATE[p] for p in PUBLIC}

    def check(self, head, enabled=True):
        return tier_check.check(entries(self.BASE), entries({**self.BASE, **head}), enabled)

    @pytest.mark.parametrize("folder", ["automations", "exclusions", "dlp-rules"])
    @pytest.mark.parametrize("tier", [None, CORE, CORE_WITH_DELAY, ENTERPRISE_ONLY])
    def test_new_yaml_rule_any_tier(self, folder, tier):
        assert self.check({f"{folder}/new.yml": rule_yaml(f"{folder}-new", tier=tier, rule_id_=None)}) == []

    @pytest.mark.parametrize("tier", [None, CORE, CORE_WITH_DELAY, ENTERPRISE_ONLY])
    def test_new_yara_any_tier(self, tier):
        assert self.check({"yara/new.yar": yara(tier, "y_new")}) == []

    def test_yara_demoted_to_enterprise_only_fails(self):
        [(path, problem)] = self.check({"yara/core.yar": yara(ENTERPRISE_ONLY, "y_core")})
        assert path == "yara/core.yar" and "Rules are never demoted" in problem

    def test_gate_applies_to_every_folder(self):
        head = {
            "automations/new.yml": rule_yaml("a-new", tier=None, rule_id_=None),
            "yara/new.yar": yara(CORE_WITH_DELAY, "y_new"),
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
            ("yara/core.yar", yara(None, "y_core")),  # removing the meta entry
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
            ("yara/leak.yar", yara(ENTERPRISE_ONLY)),
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
        assert branches == {"auto/promote-core/yara-x", "auto/promote-core/automations-a"}
        yara_branch = run_git(origin, "show", "auto/promote-core/yara-x:yara/y.yar").encode()
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
