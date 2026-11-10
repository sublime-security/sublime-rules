"""sync.py and guard.py against real git repos: a private working repo and a public clone of it."""

import os
from pathlib import Path

import pytest

import guard
import sync
from helpers import Repo, rule_path, rule_yaml, run_git
from rules import CORE, CORE_WITH_DELAY, ENTERPRISE_ONLY

MIRROR = ("Sublime Rules Mirror", "mirror@example.com")


@pytest.fixture
def private(tmp_path):
    repo = Repo(tmp_path / "private", name="Dev", email="dev@example.com")
    repo.commit(
        {
            rule_path("legacy_a"): rule_yaml("legacy_a"),
            rule_path("legacy_b"): rule_yaml("legacy_b"),
            "detection-rules/no_extension": rule_yaml("no_extension", rule_id_=None) + b"---\n",
            "yara/sig.yar": "rule x { condition: true }\n",
            "README.md": "private readme\n",
        },
        message="Initial rules (#1)",
    )
    return repo


@pytest.fixture
def public(tmp_path, private):
    """A clone with the same history, as the public repo is at cutover."""
    path = tmp_path / "public"
    run_git(tmp_path, "clone", "-q", str(private.path), str(path))
    run_git(path, "config", "user.name", MIRROR[0])
    run_git(path, "config", "user.email", MIRROR[1])
    repo = Repo.__new__(Repo)
    repo.path = path
    return repo


def run_sync(private, public, *extra, outputs=None, monkeypatch=None):
    argv = ["--private", str(private.path), "--public", str(public.path), *extra]
    return sync.main(argv)


def read_outputs(path: Path) -> dict[str, str]:
    return dict(line.split("=", 1) for line in path.read_text().splitlines())


def test_first_sync_after_cutover_makes_no_commit(private, public):  # S21
    head = public.head()
    assert run_sync(private, public) == 0
    assert public.head() == head


def test_edit_to_legacy_rule_syncs(private, public):  # S1
    private.commit({rule_path("legacy_a"): rule_yaml("legacy_a", source="type.outbound")}, message="Edit a (#2)")
    assert run_sync(private, public) == 0
    assert public.read(rule_path("legacy_a")) == private.read(rule_path("legacy_a"))


@pytest.mark.parametrize("tier, public_after", [(CORE, True), (CORE_WITH_DELAY, False), (ENTERPRISE_ONLY, False)])
def test_new_rule(private, public, tier, public_after):  # S2, S3, S4
    private.commit({rule_path("new"): rule_yaml("new", tier=tier)})
    head = public.head()
    assert run_sync(private, public) == 0
    assert (rule_path("new") in public.files()) is public_after
    assert (public.head() != head) is public_after


def test_public_tree_equals_private_public_rules(private, public):
    private.commit(
        {
            rule_path("c"): rule_yaml("c", tier=CORE),
            rule_path("d"): rule_yaml("d", tier=CORE_WITH_DELAY),
            rule_path("e"): rule_yaml("e", tier=ENTERPRISE_ONLY),
            rule_path("legacy_b"): None,
        }
    )
    assert run_sync(private, public) == 0
    expected = {p: c for p, c in private.files().items() if p not in (rule_path("d"), rule_path("e"))}
    assert public.files() == expected


def test_delete_propagates(private, public):  # S10
    private.commit({rule_path("legacy_b"): None})
    assert run_sync(private, public) == 0
    assert rule_path("legacy_b") not in public.files()


def test_rename_is_one_commit(private, public):  # S14
    private.rename(rule_path("legacy_a"), rule_path("renamed"))
    head = public.head()
    assert run_sync(private, public) == 0
    assert public.log(f"{head}..HEAD") != [""] and len(public.log(f"{head}..HEAD")) == 1
    files = public.files()
    assert rule_path("renamed") in files and rule_path("legacy_a") not in files


def test_second_run_is_a_no_op(private, public):  # S16
    private.commit({rule_path("new"): rule_yaml("new", tier=CORE)})
    assert run_sync(private, public) == 0
    head = public.head()
    assert run_sync(private, public) == 0
    assert public.head() == head


def test_many_private_commits_become_one_public_commit(private, public):
    head = public.head()
    private.commit({rule_path("one"): rule_yaml("one", tier=CORE)}, message="one (#2)")
    private.commit({rule_path("two"): rule_yaml("two", tier=ENTERPRISE_ONLY)}, message="secret two (#3)")
    private.commit({rule_path("three"): rule_yaml("three")}, message="three (#4)")
    assert run_sync(private, public) == 0
    assert len(public.log(f"{head}..HEAD")) == 1


def test_commit_message_and_identity(private, public):  # S17, S20
    private.commit(
        {
            rule_path("visible"): rule_yaml("Visible rule", tier=CORE),
            rule_path("hidden"): rule_yaml("Hidden ACME rule", tier=ENTERPRISE_ONLY),
            rule_path("legacy_b"): None,
        },
        message="Add Hidden ACME rule and Visible rule (#7)",
        author=("Dev Person", "dev@example.com"),
    )
    assert run_sync(private, public) == 0
    message = run_git(public.path, "log", "-1", "--format=%B")
    assert "ACME" not in message and "hidden" not in message and "#7" not in message
    assert message.startswith("Sync detection rules: 1 added, 1 removed\n")
    assert f"- Visible rule ({rule_path('visible')})" in message
    assert f"- legacy_b ({rule_path('legacy_b')})" in message
    assert f"Source-Commit: {private.head()}" in message
    author_committer = run_git(public.path, "log", "-1", "--format=%an <%ae>|%cn <%ce>").strip()
    assert author_committer == f"{MIRROR[0]} <{MIRROR[1]}>|{MIRROR[0]} <{MIRROR[1]}>"
    assert sync.source_commit(str(public.path), "HEAD") == private.head()


def test_long_lists_are_truncated(private, public):
    private.commit({rule_path(f"r{i:03}"): rule_yaml(f"r{i:03}") for i in range(sync.MAX_LISTED + 5)})
    assert run_sync(private, public) == 0
    message = run_git(public.path, "log", "-1", "--format=%B")
    assert "- and 5 more" in message


def test_only_detection_rules_are_touched(private, public):
    private.commit({"yara/sig.yar": "changed\n", "README.md": "changed\n", "new-dir/x.yml": "x: 1\n", rule_path("r"): rule_yaml("r")})
    run_git(public.path, "rm", "-q", "README.md")
    public.commit({"CONTRIBUTING.md": "public only\n"}, message="public bootstrap")
    assert run_sync(private, public) == 0
    tree = set(run_git(public.path, "ls-tree", "-r", "--name-only", "HEAD").split())
    assert "README.md" not in tree and "CONTRIBUTING.md" in tree and "new-dir/x.yml" not in tree
    assert public.read("yara/sig.yar") == b"rule x { condition: true }\n"
    assert rule_path("r") in tree


def test_stray_public_files_are_reverted(private, public):  # S19
    public.commit(
        {
            rule_path("stray"): rule_yaml("stray"),
            rule_path("legacy_a"): b"tampered\n",
            "detection-rules/sub/x.yml": rule_yaml("x"),
        },
        message="pushed by hand",
    )
    assert run_sync(private, public) == 0
    assert public.files() == private.files()


def test_byte_for_byte_including_crlf_and_no_newline(private, public):
    private.commit(
        {
            rule_path("crlf"): rule_yaml("crlf").replace(b"\n", b"\r\n"),
            rule_path("nonl"): rule_yaml("nonl").rstrip(b"\n"),
            "detection-rules/.gitattributes-test": rule_yaml("odd"),
        }
    )
    (public.path / ".gitattributes").write_text("* text=auto eol=crlf\n")
    public.commit({}, message="attributes")
    assert run_sync(private, public) == 0
    assert public.files() == private.files()


def test_executable_bit_is_kept(private, public):
    path = private.path / rule_path("legacy_a")
    os.chmod(path, 0o755)
    private.commit({})
    assert run_sync(private, public) == 0
    assert run_git(public.path, "ls-tree", "HEAD", rule_path("legacy_a")).startswith("100755")


def test_working_tree_is_not_read(private, public):
    (private.path / rule_path("uncommitted")).write_bytes(rule_yaml("uncommitted"))
    (private.path / rule_path("legacy_a")).write_bytes(b"dirty\n")
    head = public.head()
    assert run_sync(private, public) == 0
    assert public.head() == head


class TestFailsClosed:
    def assert_public_unchanged(self, public, head, files):
        assert public.head() == head
        assert public.files() == files

    @pytest.mark.parametrize(
        "bad",
        [
            rule_yaml("bad", tier="enterprise"),
            b"name: [\n",
            rule_yaml("bad", tier=CORE) + b"feed_tier: enterprise_only\n",
            b"# notes\n",
        ],
    )
    def test_bad_rule_blocks_everything(self, private, public, bad, capsys):  # S15
        private.commit({rule_path("good"): rule_yaml("good", tier=CORE), rule_path("bad"): bad})
        head, files = public.head(), public.files()
        assert run_sync(private, public) == 1
        self.assert_public_unchanged(public, head, files)
        assert "Nothing was synced" in capsys.readouterr().err

    def test_demotion_blocks_everything(self, private, public):  # S13
        private.commit({rule_path("legacy_a"): rule_yaml("legacy_a", tier=ENTERPRISE_ONLY), rule_path("new"): rule_yaml("new")})
        head, files = public.head(), public.files()
        assert run_sync(private, public) == 1
        self.assert_public_unchanged(public, head, files)

    def test_demotion_with_rename_blocks(self, private, public):  # S12 backstop
        private.rename(rule_path("legacy_a"), rule_path("moved"), content=rule_yaml("legacy_a", tier=CORE_WITH_DELAY))
        head = public.head()
        assert run_sync(private, public) == 1
        assert public.head() == head

    def test_duplicate_ids_block(self, private, public):
        private.commit({rule_path("dup"): rule_yaml("dup", rule_id_=rule_yaml("legacy_a").split(b'id: "')[1].split(b'"')[0].decode())})
        head = public.head()
        assert run_sync(private, public) == 1
        assert public.head() == head

    def test_symlink_blocks(self, private, public, capsys):
        # A symlink's content is its target, and this target even parses as a YAML mapping.
        os.symlink("name: looks like a rule", private.path / rule_path("link"))
        private.commit({})
        head = public.head()
        assert run_sync(private, public) == 1
        assert public.head() == head
        assert "detection-rules/link.yml is a symlink, not a regular file" in capsys.readouterr().err

    def test_submodule_blocks(self, private, public, tmp_path, capsys):
        sub = Repo(tmp_path / "sub")
        sub.commit({"x": "1"})
        run_git(private.path, "-c", "protocol.file.allow=always", "submodule", "add", "-q", str(sub.path), "detection-rules/sub")
        private.commit({})
        head = public.head()
        assert run_sync(private, public) == 1
        assert public.head() == head
        assert "detection-rules/sub is a submodule" in capsys.readouterr().err

    def test_wrong_commit_is_never_published(self, private, public, monkeypatch):
        real = sync.commit_changes

        def drops_a_change(repo, parent, changes, message, env=None):
            return real(repo, parent, dict(list(changes.items())[:-1]), message, env)

        monkeypatch.setattr(sync, "commit_changes", drops_a_change)
        private.commit({rule_path("one"): rule_yaml("one"), rule_path("two"): rule_yaml("two")})
        head = public.head()
        assert run_sync(private, public) == 1
        assert public.head() == head

    def test_recovers_once_fixed(self, private, public):
        private.commit({rule_path("bad"): rule_yaml("bad", tier="nope"), rule_path("good"): rule_yaml("good")})
        assert run_sync(private, public) == 1
        private.commit({rule_path("bad"): rule_yaml("bad", tier=ENTERPRISE_ONLY)})
        assert run_sync(private, public) == 0
        assert rule_path("good") in public.files() and rule_path("bad") not in public.files()


class TestStaleRuns:
    def test_older_private_commit_does_not_roll_back(self, private, public, tmp_path):
        old = private.head()
        private.commit({rule_path("new"): rule_yaml("new")})
        assert run_sync(private, public) == 0
        synced = public.head()

        # A delayed run that checked out the older commit.
        older = tmp_path / "older"
        run_git(tmp_path, "clone", "-q", str(private.path), str(older))
        run_git(older, "checkout", "-q", old)
        assert sync.main(["--private", str(older), "--public", str(public.path)]) == 0
        assert public.head() == synced
        assert rule_path("new") in public.files()

    def test_shallow_private_checkout_still_syncs(self, private, public, tmp_path):
        private.commit({rule_path("one"): rule_yaml("one")})
        assert run_sync(private, public) == 0
        private.commit({rule_path("two"): rule_yaml("two")})
        shallow = tmp_path / "shallow"
        run_git(tmp_path, "clone", "-q", "--depth", "1", f"file://{private.path}", str(shallow))
        assert sync.main(["--private", str(shallow), "--public", str(public.path)]) == 0
        assert rule_path("two") in public.files()

    def test_same_source_heals_drift(self, private, public):
        private.commit({rule_path("new"): rule_yaml("new")})
        assert run_sync(private, public) == 0
        public.commit({rule_path("new"): b"tampered\n"}, message="by hand")
        assert run_sync(private, public) == 0
        assert public.files() == private.files()

    def test_rewritten_private_history_still_syncs(self, private, public):
        private.commit({rule_path("new"): rule_yaml("new")})
        assert run_sync(private, public) == 0
        run_git(private.path, "reset", "-q", "--hard", "HEAD~1")
        private.commit({rule_path("other"): rule_yaml("other")})
        assert run_sync(private, public) == 0
        assert public.files() == private.files()


class TestDryRun:
    def test_changes_nothing(self, private, public, tmp_path, monkeypatch):
        outputs, summary = tmp_path / "out", tmp_path / "summary"
        monkeypatch.setenv("GITHUB_OUTPUT", str(outputs))
        monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
        private.commit({rule_path("new"): rule_yaml("new")})
        head = public.head()
        assert run_sync(private, public, "--dry-run", "true") == 0
        assert public.head() == head
        assert read_outputs(outputs) == {"changed": "false", "commit": ""}
        assert f"added: `{rule_path('new')}`" in summary.read_text()
        assert "Would sync" in summary.read_text()

    @pytest.mark.parametrize("value", ["", "false"])
    def test_false_or_unset_syncs(self, private, public, value):
        private.commit({rule_path("new"): rule_yaml("new")})
        assert run_sync(private, public, "--dry-run", value) == 0
        assert rule_path("new") in public.files()

    def test_rejects_other_values(self, private, public):
        with pytest.raises(SystemExit):
            run_sync(private, public, "--dry-run", "yes")


def test_outputs(private, public, tmp_path, monkeypatch):
    outputs = tmp_path / "out"
    monkeypatch.setenv("GITHUB_OUTPUT", str(outputs))
    private.commit({rule_path("new"): rule_yaml("new")})
    assert run_sync(private, public) == 0
    assert read_outputs(outputs) == {"changed": "true", "commit": public.head()}
    outputs.unlink()
    assert run_sync(private, public) == 0
    assert read_outputs(outputs) == {"changed": "false", "commit": ""}


def test_annotations_under_actions(private, public, monkeypatch, capsys):
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    private.commit({rule_path("bad"): rule_yaml("bad", tier="nope")})
    assert run_sync(private, public) == 1
    assert "::error::detection-rules/bad.yml: feed_tier must be one of" in capsys.readouterr().err


class TestGuard:
    def test_passes_on_public_rules(self, public):
        assert guard.main(["--repo", str(public.path)]) == 0

    @pytest.mark.parametrize("tier", [CORE_WITH_DELAY, ENTERPRISE_ONLY])
    def test_fails_on_private_tier(self, public, tier, capsys):
        public.commit({rule_path("leak"): rule_yaml("leak", tier=tier)})
        assert guard.main(["--repo", str(public.path)]) == 1
        assert f"has feed_tier {tier}" in capsys.readouterr().err

    def test_fails_on_unparseable(self, public):
        public.commit({"detection-rules/x.yml": b"[\n"})
        assert guard.main(["--repo", str(public.path)]) == 1

    def test_checks_the_given_rev_not_the_working_tree(self, public):
        good = public.head()
        public.commit({rule_path("leak"): rule_yaml("leak", tier=ENTERPRISE_ONLY)})
        assert guard.main(["--repo", str(public.path), "--rev", good]) == 0
        assert guard.main(["--repo", str(public.path), "--rev", "HEAD"]) == 1

    def test_ignores_other_directories(self, public):
        public.commit({"discovery-rules/x.yml": rule_yaml("x", tier=ENTERPRISE_ONLY)})
        assert guard.main(["--repo", str(public.path)]) == 0
