import pytest

from gittree import Entry
from helpers import rule_path, rule_yaml
from project import ProjectionError, project
from rules import CORE, CORE_WITH_DELAY, ENTERPRISE_ONLY


def entries(files: dict[str, bytes], mode: str = "100644") -> dict[str, Entry]:
    return {path: Entry(mode, content) for path, content in files.items()}


def rule(name, tier=CORE, **kwargs):
    return {rule_path(name): rule_yaml(name, tier=tier, **kwargs)}


class TestTierTable:
    @pytest.mark.parametrize(
        "tier, public", [(None, False), (CORE, True), (CORE_WITH_DELAY, False), (ENTERPRISE_ONLY, False)]
    )
    def test_new_rule(self, tier, public):
        plan = project(entries(rule("r", tier)), {})
        assert plan.added == ([rule_path("r")] if public else [])
        assert (rule_path("r") in plan.desired) is public
        assert plan.removed == [] and plan.updated == []

    def test_public_copy_is_byte_for_byte(self):
        content = rule_yaml("r", tier=CORE, source="type.inbound\n  and   weird   spacing  ") + b"\n\n# trailing\n"
        plan = project(entries({rule_path("r"): content}), {})
        assert plan.desired[rule_path("r")].content == content

    def test_mode_is_kept(self):
        plan = project(entries(rule("r", CORE), mode="100755"), entries(rule("r", CORE)))
        assert plan.updated == [rule_path("r")]
        assert plan.desired[rule_path("r")].mode == "100755"

    def test_unchanged(self):
        files = {**rule("a"), **rule("b", CORE), **rule("c", ENTERPRISE_ONLY)}
        public = {**rule("a"), **rule("b", CORE)}
        plan = project(entries(files), entries(public))
        assert not plan.changed

    def test_edit_to_public_rule(self):
        plan = project(entries(rule("r", source="type.outbound")), entries(rule("r")))
        assert plan.updated == [rule_path("r")]

    def test_edit_to_private_rule_changes_nothing(self):
        before = project(entries({**rule("p"), **rule("e", ENTERPRISE_ONLY)}), entries(rule("p")))
        after = project(entries({**rule("p"), **rule("e", ENTERPRISE_ONLY, source="changed")}), entries(rule("p")))
        assert not before.changed and not after.changed

    @pytest.mark.parametrize("from_tier", [CORE_WITH_DELAY, ENTERPRISE_ONLY])
    def test_promotion_publishes(self, from_tier):
        assert not project(entries(rule("r", from_tier)), {}).changed
        assert project(entries(rule("r", CORE)), {}).added == [rule_path("r")]

    def test_stamping_an_unstamped_public_rule_updates_it(self):
        plan = project(entries(rule("r", CORE)), entries(rule("r", None)))
        assert plan.updated == [rule_path("r")]

    def test_removing_the_core_line_is_a_demotion(self):
        with pytest.raises(ProjectionError, match=r"now has it as core_with_delay \(no feed_tier key\)"):
            project(entries(rule("r", None)), entries(rule("r", CORE)))

    def test_unstamped_rules_already_public_fail_until_stamped(self):
        # The first sync after the rename, if the existing rules weren't stamped with feed_tier: core first.
        unstamped = {**rule("a", None), **rule("b", None)}
        with pytest.raises(ProjectionError) as e:
            project(entries(unstamped), entries(unstamped))
        assert len(e.value.errors) == 2

    def test_deleted_public_rule_is_removed(self):
        plan = project(entries(rule("keep")), entries({**rule("keep"), **rule("gone")}))
        assert plan.removed == [rule_path("gone")]

    def test_rename_of_public_rule(self):
        plan = project(entries({"detection-rules/new.yml": rule_yaml("r")}), entries({"detection-rules/old.yml": rule_yaml("r")}))
        assert (plan.added, plan.removed) == (["detection-rules/new.yml"], ["detection-rules/old.yml"])

    def test_rename_and_promote(self):
        plan = project(
            entries({"detection-rules/new.yml": rule_yaml("r", tier=CORE)}),
            {},
        )
        assert plan.added == ["detection-rules/new.yml"]

    def test_stray_public_files_are_removed(self):
        public = entries(
            {
                **rule("legit"),
                **rule("stray"),
                "detection-rules/junk.txt": b"\x00 not yaml",
                "detection-rules/sub/dir.yml": rule_yaml("nested"),
                **{rule_path("leaked"): rule_yaml("leaked", tier=ENTERPRISE_ONLY, rule_id_="not-in-private")},
            }
        )
        plan = project(entries(rule("legit")), public)
        assert sorted(plan.removed) == sorted(set(public) - {rule_path("legit")})

    def test_non_yml_files_are_rules_too(self):
        # attachment_pdf_quickbooks_callback_lure has no extension and no id.
        files = {
            "detection-rules/no_extension": rule_yaml("x", rule_id_=None) + b"---\n",
            "detection-rules/hidden": rule_yaml("h", tier=ENTERPRISE_ONLY, rule_id_=None),
        }
        assert project(entries(files), {}).added == ["detection-rules/no_extension"]

    def test_nested_directories(self):
        files = {"detection-rules/a/b.yml": rule_yaml("b"), "detection-rules/a/c.yml": rule_yaml("c", tier=ENTERPRISE_ONLY)}
        assert project(entries(files), {}).added == ["detection-rules/a/b.yml"]

    def test_changes_mapping(self):
        plan = project(entries({**rule("add"), **rule("upd", source="new")}), entries({**rule("upd"), **rule("rm")}))
        assert plan.changes() == {
            rule_path("add"): plan.desired[rule_path("add")],
            rule_path("upd"): plan.desired[rule_path("upd")],
            rule_path("rm"): None,
        }


class TestFailsClosed:
    def test_unknown_tier_fails_everything(self):
        files = {**rule("good"), rule_path("bad"): rule_yaml("bad", tier=None).replace(b'id:', b"feed_tier: corez\nid:")}
        with pytest.raises(ProjectionError) as e:
            project(entries(files), {})
        assert "feed_tier must be one of" in str(e.value)

    def test_unparseable_rule_fails_everything(self):
        with pytest.raises(ProjectionError, match="not valid YAML"):
            project(entries({**rule("good"), "detection-rules/bad.yml": b"name: [\n"}), {})

    def test_non_rule_file_fails_everything(self):
        with pytest.raises(ProjectionError, match="exactly one YAML mapping"):
            project(entries({**rule("good"), "detection-rules/README.md": b"# Rules\n\nSome notes.\n"}), {})

    def test_duplicate_ids_fail(self):
        files = {rule_path("a"): rule_yaml("a", rule_id_="x"), rule_path("b"): rule_yaml("b", tier=ENTERPRISE_ONLY, rule_id_="x")}
        with pytest.raises(ProjectionError, match="more than one rule"):
            project(entries(files), {})

    def test_collects_every_problem(self):
        files = {"detection-rules/a.yml": b"[", "detection-rules/b.yml": b"feed_tier: x\n"}
        with pytest.raises(ProjectionError) as e:
            project(entries(files), {})
        assert len(e.value.errors) == 2

    @pytest.mark.parametrize("tier", [CORE_WITH_DELAY, ENTERPRISE_ONLY])
    def test_demotion_in_place_fails(self, tier):
        with pytest.raises(ProjectionError, match="never demoted"):
            project(entries(rule("r", tier)), entries(rule("r")))

    @pytest.mark.parametrize("tier", [CORE_WITH_DELAY, ENTERPRISE_ONLY])
    def test_demotion_with_rename_fails(self, tier):
        private = {"detection-rules/renamed.yml": rule_yaml("r", tier=tier)}
        with pytest.raises(ProjectionError, match="never demoted"):
            project(entries(private), entries({"detection-rules/old.yml": rule_yaml("r")}))

    def test_demotion_by_path_with_new_id_fails(self):
        private = {rule_path("r"): rule_yaml("r", tier=ENTERPRISE_ONLY, rule_id_="new-id")}
        with pytest.raises(ProjectionError, match="never demoted"):
            project(entries(private), entries({rule_path("r"): rule_yaml("r", rule_id_="old-id")}))

    def test_demotion_of_rule_without_id_fails(self):
        with pytest.raises(ProjectionError, match="never demoted"):
            project(entries(rule("r", ENTERPRISE_ONLY, rule_id_=None)), entries(rule("r", rule_id_=None)))

    def test_demotion_fails_the_whole_sync(self):
        private = {**rule("demoted", ENTERPRISE_ONLY), **rule("new_core", CORE)}
        with pytest.raises(ProjectionError):
            project(entries(private), entries(rule("demoted")))

    def test_deleting_a_public_rule_is_not_a_demotion(self):
        private = {**rule("other")}
        assert project(entries(private), entries({**rule("other"), **rule("r")})).removed == [rule_path("r")]

    def test_removing_a_stray_public_copy_of_a_private_rule_by_id_fails(self):
        # The public repo has an enterprise rule's id at some other path. The sync would remove it either way, but a
        # public copy of a private rule means something already leaked, so a human should look.
        public = {"detection-rules/copy.yml": rule_yaml("copy", rule_id_="secret-id")}
        private = {rule_path("secret"): rule_yaml("secret", tier=ENTERPRISE_ONLY, rule_id_="secret-id")}
        with pytest.raises(ProjectionError, match="never demoted"):
            project(entries(private), entries(public))

    def test_unparseable_public_file_never_blocks(self):
        plan = project(entries(rule("r", ENTERPRISE_ONLY)), entries({"detection-rules/junk.yml": b"[[["}))
        assert plan.removed == ["detection-rules/junk.yml"]
