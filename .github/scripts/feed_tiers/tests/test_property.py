"""Hypothesis state machine: random histories of rule changes and syncs against real git repos.

Invariants, checked after every sync:
- I1: the public rules are exactly the private rules whose tier is core, byte for byte (no key is core_with_delay).
- I2: the leak guard passes on the public repo.
- I3: syncing again changes nothing.
- I4: a failed sync changes nothing in the public repo.
- I5: a rule that was never public is not public.
"""

import shutil
import tempfile
from pathlib import Path

from hypothesis import HealthCheck, settings
from hypothesis import strategies as st
from hypothesis.stateful import RuleBasedStateMachine, invariant, precondition, rule

import guard
import sync
from gittree import read_tree
from helpers import Repo, rule_yaml, run_git
from rules import CORE, CORE_WITH_DELAY, ENTERPRISE_ONLY, parse_rule

NAMES = [f"r{i}" for i in range(6)]
TIERS = st.sampled_from([None, CORE, CORE_WITH_DELAY, ENTERPRISE_ONLY])
PUBLIC_TIERS = (CORE,)


class SyncMachine(RuleBasedStateMachine):
    def __init__(self):
        super().__init__()
        self.tmp = Path(tempfile.mkdtemp())
        self.private = Repo(self.tmp / "private")
        self.private.commit({"detection-rules/seed.yml": rule_yaml("seed"), "other/x.txt": "x"})
        run_git(self.tmp, "clone", "-q", str(self.private.path), str(self.tmp / "public"))
        self.public = Repo.__new__(Repo)
        self.public.path = self.tmp / "public"
        run_git(self.public.path, "config", "user.name", "Mirror")
        run_git(self.public.path, "config", "user.email", "m@example.com")
        # name -> (path, tier, version)
        self.rules = {"seed": ("detection-rules/seed.yml", CORE, 0)}
        self.ever_public = {"seed"}
        self.version = 0
        self.synced_once = False

    def teardown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def content(self, name, tier, version):
        return rule_yaml(name, tier=tier, source=f"type.inbound\nand {version} == {version}")

    def commit(self, files):
        self.version += 1
        self.private.commit(files, message=f"change {self.version}")

    @rule(name=st.sampled_from(NAMES), tier=TIERS)
    def add(self, name, tier):
        if name in self.rules:
            return
        path = f"detection-rules/{name}.yml"
        self.rules[name] = (path, tier, self.version)
        self.commit({path: self.content(name, tier, self.version)})

    @rule(data=st.data())
    def edit(self, data):
        name = data.draw(st.sampled_from(sorted(self.rules)))
        path, tier, _ = self.rules[name]
        self.rules[name] = (path, tier, self.version)
        self.commit({path: self.content(name, tier, self.version)})

    @rule(data=st.data(), new_tier=TIERS)
    def change_tier(self, data, new_tier):
        """Any tier change except demotion, which tier-check blocks."""
        name = data.draw(st.sampled_from(sorted(self.rules)))
        path, tier, version = self.rules[name]
        if tier in PUBLIC_TIERS and new_tier not in PUBLIC_TIERS:
            return
        self.rules[name] = (path, new_tier, version)
        self.commit({path: self.content(name, new_tier, version)})

    @rule(data=st.data())
    def rename(self, data):
        name = data.draw(st.sampled_from(sorted(self.rules)))
        path, tier, version = self.rules[name]
        new_path = f"detection-rules/sub{self.version % 3}/{name}_{self.version}.yml"
        self.rules[name] = (new_path, tier, version)
        self.commit({path: None, new_path: self.content(name, tier, version)})

    @precondition(lambda self: len(self.rules) > 1)
    @rule(data=st.data())
    def delete(self, data):
        name = data.draw(st.sampled_from(sorted(self.rules)))
        path, _, _ = self.rules.pop(name)
        self.commit({path: None})

    @rule(junk=st.sampled_from([b"tampered\n", b"[[[", None]), data=st.data())
    def tamper_with_public(self, junk, data):
        files = self.public.files()
        target = data.draw(st.sampled_from(sorted(files) + ["detection-rules/stray.yml"]))
        self.public.commit({target: junk} if junk is not None else {target: None}, message="by hand")

    @precondition(lambda self: any(t in PUBLIC_TIERS for _, t, _ in self.rules.values()))
    @rule(data=st.data(), to=st.sampled_from([CORE_WITH_DELAY, ENTERPRISE_ONLY, None]))
    def demotion_slips_through(self, data, to):
        """A demotion reaches main despite tier-check: the sync must refuse, then work again once it's undone."""
        name = data.draw(st.sampled_from(sorted(n for n, (_, t, _) in self.rules.items() if t in PUBLIC_TIERS)))
        path, tier, version = self.rules[name]
        if not self.synced_once or path not in self.public.files():
            return
        before = (self.public.head(), self.public.files())
        self.commit({path: self.content(name, to, version)})
        assert sync.main(["--private", str(self.private.path), "--public", str(self.public.path)]) == 1
        assert (self.public.head(), self.public.files()) == before  # I4
        self.commit({path: self.content(name, tier, version)})

    @rule()
    def unknown_tier_slips_through(self):
        before = (self.public.head(), self.public.files())
        self.commit({"detection-rules/typo.yml": rule_yaml("typo", tier="corez")})
        assert sync.main(["--private", str(self.private.path), "--public", str(self.public.path)]) == 1
        assert (self.public.head(), self.public.files()) == before  # I4
        self.commit({"detection-rules/typo.yml": None})

    @rule()
    def run_sync(self):
        assert sync.main(["--private", str(self.private.path), "--public", str(self.public.path)]) == 0
        self.synced_once = True

        private = {p: e.content for p, e in read_tree(str(self.private.path), "HEAD", "detection-rules").items()}
        public = {p: e.content for p, e in read_tree(str(self.public.path), "HEAD", "detection-rules").items()}
        expected = {p: c for p, c in private.items() if parse_rule(p, c).is_public}
        assert public == expected  # I1
        assert guard.main(["--repo", str(self.public.path)]) == 0  # I2

        head = self.public.head()
        assert sync.main(["--private", str(self.private.path), "--public", str(self.public.path)]) == 0
        assert self.public.head() == head  # I3

        public_names = {parse_rule(p, c).name for p, c in public.items()}
        self.ever_public |= public_names
        for name, (_, tier, _) in self.rules.items():
            if tier not in PUBLIC_TIERS and name not in self.ever_public:
                assert name not in public_names  # I5

    @invariant()
    def other_directories_untouched(self):
        assert self.public.read("other/x.txt") == b"x"


SyncMachine.TestCase.settings = settings(
    max_examples=40,
    stateful_step_count=20,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.filter_too_much],
)
TestSync = SyncMachine.TestCase
