import pytest
import yaml

from helpers import rule_yaml
from rules import CORE, CORE_WITH_DELAY, ENTERPRISE_ONLY, RuleError, parse_rule, parse_rules, set_tier

P = "detection-rules/r.yml"


def doc(*lines: str) -> bytes:
    return ("\n".join(lines) + "\n").encode()


BASE = ['name: "R"', 'type: "rule"', "source: |", "  type.inbound", 'id: "11111111-1111-1111-1111-111111111111"']


class TestParseRule:
    @pytest.mark.parametrize(
        "line, tier",
        [
            ("feed_tier: core", CORE),
            ("feed_tier: core_with_delay", CORE_WITH_DELAY),
            ("feed_tier: enterprise_only", ENTERPRISE_ONLY),
            ('feed_tier: "core"', CORE),
            ("feed_tier: 'enterprise_only'", ENTERPRISE_ONLY),
            ("feed_tier: core  # promoted by hand", CORE),
            ("feed_tier:   core_with_delay", CORE_WITH_DELAY),
            ('"feed_tier": enterprise_only', ENTERPRISE_ONLY),
        ],
    )
    def test_reads_tier(self, line, tier):
        assert parse_rule(P, doc(*BASE, line)).tier == tier

    def test_no_key_is_core_with_delay(self):
        rule = parse_rule(P, doc(*BASE))
        assert rule.tier is None
        assert rule.effective_tier == CORE_WITH_DELAY
        assert not rule.is_public
        assert rule.tier_label == "core_with_delay (no feed_tier key)"

    @pytest.mark.parametrize(
        "tier, public", [(CORE, True), (CORE_WITH_DELAY, False), (ENTERPRISE_ONLY, False)]
    )
    def test_is_public(self, tier, public):
        assert parse_rule(P, doc(*BASE, f"feed_tier: {tier}")).is_public is public

    def test_reads_id_and_name(self):
        rule = parse_rule(P, rule_yaml("phish", tier=CORE, rule_id_="abc"))
        assert (rule.id, rule.name, rule.label) == ("abc", "phish", f"phish ({P})")

    def test_id_is_optional(self):
        # One real rule (attachment_pdf_quickbooks_callback_lure) has no id.
        assert parse_rule(P, rule_yaml("phish", rule_id_=None)).id is None

    @pytest.mark.parametrize(
        "line",
        [
            "feed_tier: Core",
            "feed_tier: CORE",
            "feed_tier: public",
            "feed_tier: enterprise",
            "feed_tier: core-with-delay",
            "feed_tier:",
            "feed_tier: ~",
            "feed_tier: null",
            "feed_tier: 1",
            "feed_tier: yes",
            "feed_tier: [core]",
            "feed_tier: {tier: core}",
            'feed_tier: ""',
        ],
    )
    def test_rejects_unknown_tier(self, line):
        with pytest.raises(RuleError, match="feed_tier must be one of"):
            parse_rule(P, doc(*BASE, line))

    def test_rejects_duplicate_tier_key(self):
        with pytest.raises(RuleError, match="duplicate key 'feed_tier'"):
            parse_rule(P, doc(*BASE, "feed_tier: core", "feed_tier: enterprise_only"))

    def test_rejects_duplicate_tier_key_even_when_last_is_core(self):
        # Without duplicate detection, PyYAML would keep the last value and call this rule core.
        with pytest.raises(RuleError, match="duplicate key"):
            parse_rule(P, doc(*BASE, "feed_tier: enterprise_only", "feed_tier: core"))

    def test_rejects_duplicate_other_key(self):
        with pytest.raises(RuleError, match="duplicate key 'id'"):
            parse_rule(P, doc(*BASE, 'id: "other"'))

    def test_ignores_feed_tier_text_inside_source(self):
        content = doc('name: "R"', "source: |", "  feed_tier: enterprise_only", "  and type.inbound", 'id: "x"')
        assert parse_rule(P, content).tier is None

    def test_ignores_feed_tier_text_inside_description(self):
        content = doc('name: "R"', 'description: "feed_tier: enterprise_only"', 'id: "x"')
        assert parse_rule(P, content).tier is None

    def test_rejects_tier_set_through_merge_key(self):
        # Valid YAML that sets the tier without a plain line, which promote.py couldn't edit.
        content = doc("base: &b", "  feed_tier: enterprise_only", "<<: *b", 'name: "R"')
        with pytest.raises(RuleError, match="one plain top-level line"):
            parse_rule(P, content)

    def test_rejects_flow_style_mapping(self):
        with pytest.raises(RuleError, match="one plain top-level line"):
            parse_rule(P, b'{name: "R", feed_tier: core}\n')

    def test_rejects_column_zero_tier_line_inside_multiline_string(self):
        # If a multi-line scalar ever parses with a column-0 "feed_tier:" continuation line, the line count and the
        # parsed document disagree, and that's an error rather than a guess.
        content = doc('name: "R"', 'description: "first', 'feed_tier: enterprise_only"', 'id: "x"')
        try:
            parsed = yaml.safe_load(content)
        except yaml.YAMLError:
            parsed = None
        with pytest.raises(RuleError):
            parse_rule(P, content)
        assert parsed is None or "feed_tier" not in parsed

    def test_rejects_indented_document(self):
        with pytest.raises(RuleError, match="one plain top-level line"):
            parse_rule(P, doc("  name: R", "  feed_tier: core"))

    def test_trailing_document_separator_is_allowed(self):
        # attachment_pdf_quickbooks_callback_lure ends with "---".
        assert parse_rule(P, doc(*BASE, "feed_tier: core", "---")).tier == CORE

    def test_leading_document_separator_is_allowed(self):
        assert parse_rule(P, doc("---", *BASE, "feed_tier: enterprise_only")).tier == ENTERPRISE_ONLY

    def test_rejects_two_documents(self):
        with pytest.raises(RuleError, match="exactly one YAML mapping"):
            parse_rule(P, doc(*BASE, "---", 'name: "second"', "feed_tier: enterprise_only"))

    @pytest.mark.parametrize("content", [b"", b"---\n", b"- a\n- b\n", b"just a string\n", b"# only a comment\n"])
    def test_rejects_non_mapping(self, content):
        with pytest.raises(RuleError, match="exactly one YAML mapping"):
            parse_rule(P, content)

    def test_rejects_invalid_yaml(self):
        with pytest.raises(RuleError, match="not valid YAML"):
            parse_rule(P, b'name: "R\nsource: [\n')

    def test_rejects_invalid_utf8(self):
        with pytest.raises(RuleError, match="not valid UTF-8"):
            parse_rule(P, b'name: "\xff"\n')

    def test_crlf_line_endings(self):
        assert parse_rule(P, doc(*BASE, "feed_tier: enterprise_only").replace(b"\n", b"\r\n")).tier == ENTERPRISE_ONLY

    def test_no_trailing_newline(self):
        assert parse_rule(P, doc(*BASE, "feed_tier: core_with_delay").rstrip(b"\n")).tier == CORE_WITH_DELAY

    @pytest.mark.parametrize("line", ["id: 7", "id: ''", "id: [a]", "id: ~"])
    def test_rejects_bad_id(self, line):
        content = doc('name: "R"', line)
        if line == "id: ~":
            assert parse_rule(P, content).id is None
            return
        with pytest.raises(RuleError, match="id must be"):
            parse_rule(P, content)

    def test_similar_keys_are_not_the_tier(self):
        rule = parse_rule(P, doc(*BASE, "feed_tiers: enterprise_only", "feed_tier_note: enterprise_only"))
        assert rule.tier is None

    def test_rejects_python_tags(self):
        with pytest.raises(RuleError, match="not valid YAML"):
            parse_rule(P, doc(*BASE, "x: !!python/object/apply:os.system ['true']"))


class TestParseRules:
    def test_collects_every_error(self):
        rules, errors = parse_rules(
            {
                "detection-rules/a.yml": b"feed_tier: nope\n",
                "detection-rules/b.yml": b"[",
                "detection-rules/c.yml": rule_yaml("c"),
            }
        )
        assert list(rules) == ["detection-rules/c.yml"]
        assert len(errors) == 2

    def test_duplicate_ids(self):
        _, errors = parse_rules(
            {
                "detection-rules/a.yml": rule_yaml("a", rule_id_="same"),
                "detection-rules/b.yml": rule_yaml("b", tier=ENTERPRISE_ONLY, rule_id_="same"),
            }
        )
        assert errors == ["id same is used by more than one rule: detection-rules/a.yml, detection-rules/b.yml"]

    def test_rules_without_ids_never_collide(self):
        _, errors = parse_rules(
            {"detection-rules/a": rule_yaml("a", rule_id_=None), "detection-rules/b": rule_yaml("b", rule_id_=None)}
        )
        assert errors == []


class TestSetTier:
    def test_changes_only_the_tier_line(self):
        before = rule_yaml("r", tier=CORE_WITH_DELAY, source="type.inbound\nand any(attachments, .size > 10)")
        after = set_tier(P, before, CORE)
        before_lines, after_lines = before.split(b"\n"), after.split(b"\n")
        assert len(before_lines) == len(after_lines)
        diff = [(a, b) for a, b in zip(before_lines, after_lines) if a != b]
        assert diff == [(b"feed_tier: core_with_delay", b"feed_tier: core")]

    def test_keeps_crlf(self):
        before = rule_yaml("r", tier=CORE_WITH_DELAY).replace(b"\n", b"\r\n")
        after = set_tier(P, before, CORE)
        assert after == before.replace(b"feed_tier: core_with_delay\r\n", b"feed_tier: core\r\n")

    def test_tier_on_last_line_without_newline(self):
        before = doc(*BASE, "feed_tier: core_with_delay").rstrip(b"\n")
        assert set_tier(P, before, CORE).endswith(b"\nfeed_tier: core")

    def test_drops_quotes_and_comment_on_that_line_only(self):
        before = doc(*BASE, 'feed_tier: "core_with_delay"  # 90 days')
        assert set_tier(P, before, CORE) == doc(*BASE, "feed_tier: core")

    def test_source_with_tier_text_is_untouched(self):
        before = doc('name: "R"', "source: |", "  feed_tier: core_with_delay", "feed_tier: core_with_delay", 'id: "x"')
        after = set_tier(P, before, CORE)
        assert after == doc('name: "R"', "source: |", "  feed_tier: core_with_delay", "feed_tier: core", 'id: "x"')

    def test_preserves_odd_formatting_elsewhere(self):
        before = doc("# leading comment", 'name:    "R"   # note', "source: |-", "    type.inbound", "", "feed_tier: core_with_delay", "")
        after = set_tier(P, before, CORE)
        assert after == before.replace(b"feed_tier: core_with_delay", b"feed_tier: core")

    def test_no_tier_line_is_added_above_id(self):
        assert set_tier(P, doc(*BASE), CORE) == doc(*BASE[:-1], "feed_tier: core", BASE[-1])

    def test_no_tier_line_and_no_id_appends(self):
        assert set_tier(P, doc(*BASE[:-1]), CORE) == doc(*BASE[:-1], "feed_tier: core")

    def test_no_tier_line_appends_after_a_missing_final_newline(self):
        before = doc("source: |", "  type.inbound", 'name: "R"').rstrip(b"\n")
        assert set_tier(P, before, CORE) == doc("source: |", "  type.inbound", 'name: "R"', "feed_tier: core")

    def test_no_final_newline_after_a_block_scalar_fails(self):
        # The scalar's value has no trailing newline; adding one would change it.
        with pytest.raises(RuleError, match="would change other keys"):
            set_tier(P, doc(*BASE[:-1]).rstrip(b"\n"), CORE)

    def test_no_tier_line_keeps_crlf(self):
        before = doc(*BASE).replace(b"\n", b"\r\n")
        assert set_tier(P, before, CORE) == doc(*BASE[:-1], "feed_tier: core", BASE[-1]).replace(b"\n", b"\r\n")

    def test_id_inside_source_is_not_the_id_line(self):
        before = doc('name: "R"', "source: |", "  id: not this one", "  type.inbound")
        assert set_tier(P, before, CORE) == before + b"feed_tier: core\n"

    def test_adding_a_line_that_would_change_a_value_fails(self):
        # Appending to a keep-chomped block scalar with no final newline would add a newline to its value.
        with pytest.raises(RuleError, match="would change other keys"):
            set_tier(P, doc('name: "R"', "source: |+", "  type.inbound").rstrip(b"\n"), CORE)

    def test_added_line_reparses_for_every_tier(self):
        for tier in (CORE, CORE_WITH_DELAY, ENTERPRISE_ONLY):
            assert parse_rule(P, set_tier(P, doc(*BASE), tier)).tier == tier

    def test_invalid_rule(self):
        with pytest.raises(RuleError):
            set_tier(P, doc(*BASE, "feed_tier: bogus"), CORE)

    def test_unknown_target_tier(self):
        with pytest.raises(ValueError):
            set_tier(P, doc(*BASE, "feed_tier: core_with_delay"), "bogus")

    def test_result_reparses(self):
        for tier in (CORE, CORE_WITH_DELAY, ENTERPRISE_ONLY):
            assert parse_rule(P, set_tier(P, doc(*BASE, "feed_tier: core_with_delay"), tier)).tier == tier
