"""YARA files whose rules have different tiers: each rule's own tier, the public copy with only the core rules, and
each script handling YARA rules one by one."""

from datetime import datetime, timedelta, timezone

import pytest
import yara as libyara

import default_tier
import guard
import promote
import stamp_core
import sync
import tier_check
from gitdates import delayed_since
from gittree import Entry, read_tree
from helpers import Repo, run_git
from project import ProjectionError, project
from rules import CORE, CORE_WITH_DELAY, ENTERPRISE_ONLY, MANAGED_DIRS, RuleError, parse_file, parse_rules, public_content, set_tier

P = "yara/m.yar"

A_CORE = b'''rule a_core
{
    meta:
        author = "x"
        feed_tier = "core"
    condition:
        pe.is_pe
}
'''
B_ENT = b'''private rule b_ent
{
    meta:
        feed_tier = "enterprise_only"
    strings:
        $s = "secret-2027-campaign"
    condition:
        $s
}
'''
C_DELAYED = b'''rule c_delayed
{
    meta:
        feed_tier = "core_with_delay"
    condition:
        b_ent
}
'''
D_CORE = b'''rule d_core : tag1
{
    meta:
        feed_tier = "core"
    strings:
        $a = "x"
    condition:
        a_core and filesize < 100 and any of ($a*)
}
'''
MIXED = (
    b'import "pe"\n// Header: about every rule here, including the private ones.\n\n'
    + A_CORE
    + b"\n/* b_ent catches the 2027 campaign */\n"
    + B_ENT
    + b"\n"
    + C_DELAYED
    + b"\n"
    + D_CORE
)
PUBLIC = b'import "pe"\n\n' + A_CORE + b"\n" + D_CORE


def entries(files):
    return {p: Entry("100644", c) for p, c in files.items()}


def compiled_names(content: bytes) -> set[str]:
    return {rule.identifier for rule in libyara.compile(source=content.decode())}


def simple(name: str, tier: str | None, condition: str = "true") -> bytes:
    meta = f'    meta:\n        feed_tier = "{tier}"\n' if tier else ""
    return f"rule {name}\n{{\n{meta}    condition:\n        {condition}\n}}\n".encode()


class TestPublicContent:
    def test_each_rule_has_its_own_tier(self):
        rules = parse_file(P, MIXED)
        assert [(r.yara_name, r.effective_tier) for r in rules] == [
            ("a_core", CORE),
            ("b_ent", ENTERPRISE_ONLY),
            ("c_delayed", CORE_WITH_DELAY),
            ("d_core", CORE),
        ]

    def test_only_the_core_rules_exactly_as_written(self):
        assert public_content(P, MIXED) == PUBLIC

    def test_nothing_from_the_other_rules_or_comments(self):
        public = public_content(P, MIXED)
        for private in (b"b_ent", b"c_delayed", b"secret", b"2027", b"Header", b"/*"):
            assert private not in public

    def test_libyara_compiles_it(self):
        assert compiled_names(MIXED) == {"a_core", "b_ent", "c_delayed", "d_core"}
        assert compiled_names(public_content(P, MIXED)) == {"a_core", "d_core"}

    def test_every_rule_core_is_the_whole_file(self):
        content = b"// comments stay\n" + A_CORE.replace(b"pe.is_pe", b"true") + b"\n" + simple("e", CORE)
        assert public_content(P, content) == content

    @pytest.mark.parametrize("tier", [None, CORE_WITH_DELAY, ENTERPRISE_ONLY])
    def test_no_core_rule_is_nothing(self, tier):
        assert public_content(P, simple("a", tier) + simple("b", ENTERPRISE_ONLY)) is None

    def test_no_import_when_the_core_rules_use_no_module(self):
        content = b'import "pe"\n' + simple("a", CORE) + simple("b", ENTERPRISE_ONLY, "pe.is_pe")
        assert public_content(P, content) == simple("a", CORE)

    def test_crlf(self):
        crlf = MIXED.replace(b"\n", b"\r\n")
        assert public_content(P, crlf) == PUBLIC.replace(b"\n", b"\r\n")

    def test_last_rule_without_a_final_newline(self):
        content = simple("a", ENTERPRISE_ONLY) + simple("b", CORE).rstrip(b"\n")
        assert public_content(P, content) == simple("b", CORE)

    def test_core_rule_using_another_core_rule_is_fine(self):
        assert public_content(P, MIXED).count(b"a_core") == 2  # defined, and used by d_core

    @pytest.mark.parametrize(
        "content, problem",
        [
            (
                MIXED.replace(b"a_core and filesize", b"c_delayed and filesize"),
                "core rule d_core uses rule c_delayed, which is core_with_delay",
            ),
            (
                MIXED.replace(b"a_core and filesize", b"b_ent and filesize"),
                "core rule d_core uses rule b_ent, which is enterprise_only",
            ),
            (MIXED.replace(b"private rule b_ent", b"global rule b_ent"), "rule b_ent is global"),
            (b'include "other.yar"\n' + MIXED, "it has an include line"),
            (MIXED.replace(b"any of ($a*)", b"any of (c_*)"), "core rule d_core uses a rule set"),
            (
                simple("e", CORE).rstrip(b"\n") + b" " + simple("f", ENTERPRISE_ONLY),
                "rule f doesn't start and end on lines of its own",
            ),
            (b"/* x */ " + simple("e", CORE) + simple("f", ENTERPRISE_ONLY), "rule e doesn't start and end"),
        ],
    )
    def test_mixed_files_that_cant_be_split_fail(self, content, problem):
        with pytest.raises(RuleError, match="only its core rules are published") as e:
            parse_file(P, content)
        assert problem in str(e.value)
        with pytest.raises(RuleError):
            public_content(P, content)

    def test_the_same_things_are_fine_when_every_rule_has_one_tier(self):
        content = b'include "other.yar"\nglobal ' + simple("e", ENTERPRISE_ONLY) + simple("f", ENTERPRISE_ONLY, "e")
        assert [r.tier for r in parse_file(P, content)] == [ENTERPRISE_ONLY, ENTERPRISE_ONLY]

    def test_string_sets_and_arithmetic_are_not_rule_sets(self):
        content = simple("e", CORE, "filesize*2 > 10 and any of them") + simple("f", ENTERPRISE_ONLY)
        assert public_content(P, content) == simple("e", CORE, "filesize*2 > 10 and any of them")

    def test_two_rules_with_one_name_fail(self):
        with pytest.raises(RuleError, match="more than one YARA rule named e"):
            parse_file(P, simple("e", CORE) + simple("e", ENTERPRISE_ONLY))

    def test_one_name_in_two_files_fails(self):
        _, errors = parse_rules({"yara/a.yar": simple("e", CORE), "yara/b.yar": simple("e", ENTERPRISE_ONLY)})
        assert errors == ["YARA rule name e is used more than once: yara/a.yar, yara/b.yar"]


class TestSetTier:
    def test_only_the_named_rule_changes(self):
        promoted = set_tier(P, MIXED, CORE, ["c_delayed"])
        assert promoted == MIXED.replace(b'feed_tier = "core_with_delay"', b'feed_tier = "core"')

    def test_only_rules_without_one_get_it(self):
        content = simple("e", ENTERPRISE_ONLY) + simple("f", None)
        assert set_tier(P, content, CORE_WITH_DELAY, ["f"]) == simple("e", ENTERPRISE_ONLY) + simple("f", CORE_WITH_DELAY)

    def test_unknown_name_fails(self):
        with pytest.raises(RuleError, match="has no YARA rule named nope"):
            set_tier(P, MIXED, CORE, ["nope"])

    def test_names_only_for_yara(self):
        with pytest.raises(ValueError):
            set_tier("detection-rules/x.yml", b"name: x\n", CORE, ["x"])


class TestProjection:
    def test_publishes_the_core_rules(self):
        plan = project(entries({P: MIXED}), {})
        assert plan.added == [P] and plan.desired[P].content == PUBLIC

    def test_promoting_a_rule_updates_the_file(self):
        content = MIXED.replace(b"        b_ent\n", b"        true\n")
        public = entries({P: public_content(P, content)})
        plan = project(entries({P: set_tier(P, content, CORE, ["c_delayed"])}), public)
        assert plan.updated == [P]
        assert compiled_names(plan.desired[P].content) == {"a_core", "c_delayed", "d_core"}

    def test_deleting_a_rule_removes_it(self):
        public = entries({P: PUBLIC})
        plan = project(entries({P: MIXED.replace(D_CORE, b"")}), public)
        assert plan.updated == [P] and b"d_core" not in plan.desired[P].content

    def test_deleting_every_core_rule_removes_the_file(self):
        plan = project(entries({P: B_ENT}), entries({P: PUBLIC}))
        assert plan.removed == [P]

    def test_demoting_one_rule_fails(self):
        demoted = MIXED.replace(D_CORE, D_CORE.replace(b'feed_tier = "core"', b'feed_tier = "enterprise_only"'))
        with pytest.raises(ProjectionError, match="YARA rule d_core in yara/m.yar is public, but the private repo now has it as enterprise_only"):
            project(entries({P: demoted}), entries({P: PUBLIC}))

    def test_moving_a_public_rule_into_another_file_as_enterprise_only_fails(self):
        moved = D_CORE.replace(b'feed_tier = "core"', b'feed_tier = "enterprise_only"')
        with pytest.raises(ProjectionError, match="YARA rule d_core .* at yara/other.yar"):
            project(entries({P: MIXED.replace(D_CORE, b""), "yara/other.yar": moved}), entries({P: PUBLIC}))

    def test_a_mixed_file_that_cant_be_split_fails_the_whole_sync(self):
        bad = MIXED.replace(b"a_core and filesize", b"b_ent and filesize")
        with pytest.raises(ProjectionError, match="core rule d_core uses rule b_ent"):
            project(entries({P: bad}), {})


class TestTierCheck:
    def check(self, base, head, enabled=True):
        return tier_check.check(entries(base), entries(head), enabled)

    def test_new_mixed_file(self):
        assert self.check({}, {P: MIXED}) == []

    def test_demoting_one_rule_fails(self):
        demoted = MIXED.replace(D_CORE, D_CORE.replace(b'feed_tier = "core"', b'author = "y"'))
        [(path, problem)] = self.check({P: MIXED}, {P: demoted})
        assert path == P and problem.startswith("YARA rule d_core is public, so it can't become core_with_delay")

    def test_demoting_a_rule_while_moving_it_fails(self):
        moved = D_CORE.replace(b'feed_tier = "core"', b'feed_tier = "enterprise_only"')
        problems = self.check({P: MIXED}, {P: MIXED.replace(D_CORE, b""), "yara/other.yar": moved})
        assert problems == [
            ("yara/other.yar", "YARA rule d_core is public, so it can't become enterprise_only. Rules are never demoted: to take it out of the public feed, delete it.")
        ]

    def test_gate_names_each_rule(self):
        problems = self.check({}, {P: MIXED}, enabled=False)
        assert [problem for _, problem in problems] == [
            'YARA rule b_ent is enterprise_only, which isn\'t allowed yet: set feed_tier = "core" in its meta (NON_CORE_TIERS_ENABLED is off)',
            'YARA rule c_delayed is core_with_delay, which isn\'t allowed yet: set feed_tier = "core" in its meta (NON_CORE_TIERS_ENABLED is off)',
        ]

    def test_promoting_a_rule_that_uses_a_private_rule_fails(self):
        [(path, problem)] = self.check({P: MIXED}, {P: set_tier(P, MIXED, CORE, ["c_delayed"])})
        assert "core rule c_delayed uses rule b_ent, which is enterprise_only" in problem

    def test_reusing_a_name_fails(self):
        [(path, problem)] = self.check({P: MIXED}, {P: MIXED, "yara/other.yar": simple("a_core", CORE)})
        assert path == "yara/other.yar" and problem == "YARA rule name a_core is used more than once: yara/m.yar, yara/other.yar"


class TestGuard:
    def test_public_copy_passes(self):
        assert guard.check(entries({P: PUBLIC})) == []

    def test_whole_mixed_file_fails(self):
        problems = guard.check(entries({P: MIXED}))
        assert "yara/m.yar: libyara reads YARA rule b_ent as feed_tier 'enterprise_only', so it must not be public" in problems
        assert "YARA rule c_delayed (yara/m.yar): is core_with_delay and must not be public" in problems

    def test_a_rule_without_a_tier_fails(self):
        problems = guard.check(entries({P: simple("e", None)}))
        assert "yara/m.yar: libyara reads YARA rule e as feed_tier None, so it must not be public" in problems

    def test_a_file_libyara_cant_compile_fails(self):
        [problem] = guard.check(entries({P: simple("e", CORE, "undefined_rule")}))
        assert problem.startswith("yara/m.yar: libyara can't compile it")

    def test_include_fails(self):
        problems = guard.check(entries({P: b'include "other.yar"\n' + simple("e", CORE)}))
        assert any("libyara can't compile it" in p for p in problems)


@pytest.fixture
def repos(tmp_path):
    private = Repo(tmp_path / "private")
    private.commit({"README.md": "x\n"})
    public_path = tmp_path / "public"
    run_git(tmp_path, "clone", "-q", str(private.path), str(public_path))
    run_git(public_path, "config", "user.name", "Mirror")
    run_git(public_path, "config", "user.email", "mirror@example.com")
    return private, public_path


class TestSync:
    def test_sync_and_guard(self, repos):
        private, public = repos
        private.commit({P: MIXED})
        result = sync.sync(str(private.path), str(public))
        assert result.commit is not None
        assert {p: e.content for p, e in read_tree(public, "HEAD", MANAGED_DIRS).items()} == {P: PUBLIC}
        assert guard.main(["--repo", str(public)]) == 0
        message = run_git(public, "log", "-1", "--format=%B")
        assert "b_ent" not in message and "c_delayed" not in message


T0 = datetime(2027, 1, 1, 12, tzinfo=timezone.utc)


def day(n):
    return T0 + timedelta(days=n)


class FakeGitHub:
    def __init__(self):
        self.prs = []

    def find_open_pr(self, branch):
        return next((pr["url"] for pr in self.prs if pr["branch"] == branch), None)

    def create_pr(self, *, branch, base, title, body, label):
        url = f"https://github.example/pr/{len(self.prs) + 1}"
        self.prs.append(dict(branch=branch, title=title, body=body, url=url))
        return url

    def dispatch_workflow(self, workflow, ref):
        pass


def two_rules(a_tier, b_tier, a_condition="true", b_condition="true"):
    content = simple("a", a_tier, a_condition)
    if b_tier is not False:
        content += b"\n" + simple("b", b_tier, b_condition)
    return content


class TestPromote:
    @pytest.fixture
    def repo(self, tmp_path):
        origin = tmp_path / "origin.git"
        run_git(tmp_path, "init", "-q", "--bare", "-b", "main", str(origin))
        r = Repo(tmp_path / "work", name="github-actions[bot]", email="bot@example.com")
        r.commit({"README.md": "x\n"}, when=day(-500))
        run_git(r.path, "remote", "add", "origin", str(origin))
        r.origin = origin
        return r

    def test_each_rule_has_its_own_clock(self, repo):
        repo.commit({P: two_rules(CORE_WITH_DELAY, False)}, when=day(0))
        repo.commit({P: two_rules(CORE_WITH_DELAY, CORE_WITH_DELAY)}, when=day(45))
        repo.commit({P: two_rules(CORE_WITH_DELAY, CORE_WITH_DELAY, a_condition="filesize > 1")}, when=day(60))
        repo.commit({P: two_rules(CORE_WITH_DELAY, CORE_WITH_DELAY, "filesize > 1", "filesize > 2")}, when=day(70))
        found, errors = promote.candidates(str(repo.path))
        assert errors == []
        assert {c.rule.yara_name: c.delayed_since for c in found} == {"a": day(0), "b": day(45)}

        github = FakeGitHub()
        promote.promote(str(repo.path), github, day(89))
        assert github.prs == []

        promote.promote(str(repo.path), github, day(90))
        [pr] = github.prs
        assert pr["branch"] == "auto/promote-core/yara-a"
        assert pr["title"] == "Promote a to core"
        assert pr["body"].startswith("YARA rule `a` in `yara/m.yar` has been `core_with_delay` since 2027-01-01, 90 days ago.")
        head = repo.read(P)
        promoted = run_git(repo.origin, "show", f"auto/promote-core/yara-a:{P}").encode()
        assert promoted == set_tier(P, head, CORE, ["a"])
        assert [r.tier for r in parse_file(P, promoted)] == [CORE, CORE_WITH_DELAY]

        promote.promote(str(repo.path), github, day(135))
        assert [pr["branch"] for pr in github.prs] == ["auto/promote-core/yara-a", "auto/promote-core/yara-b"]

    def test_becoming_core_with_delay_starts_the_clock(self, repo):
        repo.commit({P: two_rules(ENTERPRISE_ONLY, CORE)}, when=day(-300))
        repo.commit({P: two_rules(CORE_WITH_DELAY, CORE)}, when=day(0))
        [candidate], _ = promote.candidates(str(repo.path))
        assert candidate.delayed_since == day(0)

    def test_another_rule_changing_tier_does_not_move_it(self, repo):
        repo.commit({P: two_rules(CORE_WITH_DELAY, ENTERPRISE_ONLY)}, when=day(0))
        repo.commit({P: two_rules(CORE_WITH_DELAY, CORE)}, when=day(30))
        [candidate], _ = promote.candidates(str(repo.path))
        assert candidate.rule.yara_name == "a" and candidate.delayed_since == day(0)

    def test_moving_to_another_file_keeps_the_clock(self, repo):
        repo.commit({P: two_rules(CORE_WITH_DELAY, CORE)}, when=day(0))
        repo.commit({P: simple("b", CORE), "yara/other.yar": simple("a", CORE_WITH_DELAY)}, when=day(20))
        [candidate], _ = promote.candidates(str(repo.path))
        assert candidate.rule.path == "yara/other.yar" and candidate.delayed_since == day(0)

    def test_renaming_starts_it_again(self, repo):
        repo.commit({P: two_rules(CORE_WITH_DELAY, CORE)}, when=day(0))
        repo.commit({P: two_rules(CORE_WITH_DELAY, CORE).replace(b"rule a", b"rule a2")}, when=day(20))
        [candidate], _ = promote.candidates(str(repo.path))
        assert candidate.delayed_since == day(20)

    def test_delayed_since_directly(self, repo):
        repo.commit({P: two_rules(None, CORE)}, when=day(0))
        repo.commit({P: two_rules(CORE_WITH_DELAY, CORE)}, when=day(5))  # the default line, made visible
        [rule] = [r for r in parse_file(P, repo.read(P)) if r.yara_name == "a"]
        assert delayed_since(str(repo.path), rule) == day(0)


class TestDefaultTierAndStamp:
    def test_default_tier_adds_it_only_where_missing(self):
        content = simple("e", ENTERPRISE_ONLY) + simple("f", None) + simple("g", CORE)
        result = default_tier.missing_tiers({}, entries({P: content}))
        assert result.updates[P].content == simple("e", ENTERPRISE_ONLY) + simple("f", CORE_WITH_DELAY) + simple("g", CORE)

    def test_stamp_only_where_missing(self, tmp_path):
        repo = Repo(tmp_path / "r")
        repo.commit({P: simple("e", ENTERPRISE_ONLY) + simple("f", None)})
        assert stamp_core.stamp(repo.path) == [P]
        assert (repo.path / P).read_bytes() == simple("e", ENTERPRISE_ONLY) + simple("f", CORE)
