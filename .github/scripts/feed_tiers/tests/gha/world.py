"""A simulated GitHub that runs the real workflow files against local bare repos.

What it models, because the sync depends on it:
- Repos are bare git repos. A pre-receive hook (hook.py) enforces who may push where: branch protection on the
  private main (only merges), the public repo's ruleset (only the mirror deploy key), GITHUB_TOKEN permissions,
  deploy keys being per repo, and persist-credentials: false leaving no credential at all.
- Workflows are read from the repo at the triggering commit, like GitHub does. Triggers, the job `if:`,
  permissions, environments (secrets only on main), step `if:`, env, working-directory and step outputs are
  evaluated as Actions would. `run:` steps run in bash with the real scripts; actions/checkout is reimplemented
  (ref, path, fetch-depth, ssh-key, persist-credentials). gh is fake_gh.py.
- PRs, required checks and the merge queue: a PR can only merge once tier-check has passed on its head commit,
  and then on the queued squash commit (merge_group). PRs opened with GITHUB_TOKEN trigger no workflows; their
  checks come only from workflow_dispatch runs.
- The repo rename at cutover, and a new public repo created from the same history.
- A clock: every commit the world or a workflow makes is dated by it.

Not modeled: rule-validate (it calls the Sublime API), so a dispatched run of it just records success; scheduling
and concurrency (tests call runs in the order they want, including skipping runs).
"""

from __future__ import annotations

import json
import os
import shlex
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path

import yaml

from . import expressions

HERE = Path(__file__).resolve().parent
SCRIPTS_DIR = HERE.parent.parent  # .github/scripts/feed_tiers
REPO_ROOT = SCRIPTS_DIR.parent.parent.parent

ORG = "sublime-security"
OLD_NAME = f"{ORG}/sublime-rules"
PRIVATE = f"{ORG}/sublime-rules-enterprise"
PUBLIC = f"{ORG}/sublime-rules"

SIMULATED_WORKFLOWS = ("sync-public.yml", "promote-delayed.yml", "tier-check.yml")
COPIED_WORKFLOWS = SIMULATED_WORKFLOWS + ("rule-validate.yml",)
REQUIRED_CHECKS = ("tier-check",)
MIRROR_KEY = "mirror-deploy-key-1"
SIM_GITHUB = ("GitHub", "noreply@github.com")


class MergeBlocked(Exception):
    pass


@dataclass
class StepResult:
    name: str
    outcome: str  # success, failure, skipped
    log: str = ""
    outputs: dict = field(default_factory=dict)


@dataclass
class RunResult:
    workflow: str
    event: str
    conclusion: str  # success, failure, skipped
    steps: list[StepResult] = field(default_factory=list)
    sha: str = ""
    reason: str = ""

    @property
    def ok(self) -> bool:
        return self.conclusion == "success"

    def step(self, name: str) -> StepResult:
        for step in self.steps:
            if step.name == name:
                return step
        raise KeyError(f"no step {name!r} in {[s.name for s in self.steps]}")

    @property
    def log(self) -> str:
        return "\n".join(f"--- {s.name} [{s.outcome}]\n{s.log}" for s in self.steps) + (f"\n{self.reason}" if self.reason else "")

    def __repr__(self):
        return f"RunResult({self.workflow}, {self.event}, {self.conclusion})\n{self.log}"


def _git(cwd, *args, env=None, input=None, check=True) -> str:
    result = subprocess.run(
        ["git", *args], cwd=cwd, capture_output=True, input=input, env={**os.environ, **(env or {})}
    )
    if check and result.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} failed in {cwd}:\n{result.stderr.decode(errors='replace')}")
    return result.stdout.decode(errors="replace")


class World:
    def __init__(self, root: Path, start: datetime, initial_files: dict[str, bytes]):
        self.root = Path(root)
        self.clock = start
        self.repos: dict[str, Path] = {}
        self.policies: dict[str, dict] = {}
        self.vars: dict[str, dict] = {}
        self.environments: dict[str, dict[str, dict]] = {}  # repo -> environment -> secrets
        self.checks: dict[str, dict[str, str]] = {}  # sha -> check name -> conclusion
        self.runs: list[RunResult] = []
        self._run_count = 0
        self._work: dict[tuple[str, str], Path] = {}

        self.bin = self.root / "bin"
        self.bin.mkdir(parents=True)
        python = self.bin / "python"
        python.write_text(f'#!/bin/sh\nexec "{sys.executable}" "$@"\n')
        python.chmod(0o755)
        gh = self.bin / "gh"
        gh.write_text(f'#!/bin/sh\nexec "{sys.executable}" "{HERE / "fake_gh.py"}" "$@"\n')
        gh.chmod(0o755)

        self.state_file = self.root / "github-state.json"
        self._save_state({"settings": {}, "labels": {}, "prs": [], "dispatches": [], "next_number": 1})

        # Today's public repo, before the rename: anyone can open PRs, only merges reach main.
        self._create_repo(OLD_NAME, main_writers=["merge", "admin"], branch_writers=["dev", "token", "merge", "admin"])
        files = {**self._workflow_and_script_files(), **initial_files}
        self.commit(OLD_NAME, files, message="Initial commit", credential="admin", author=("Seed", "seed@example.com"))

    # ----- time -----------------------------------------------------------------------------------------------

    def advance(self, days: float = 0, **kwargs) -> datetime:
        self.clock += timedelta(days=days, **kwargs)
        return self.clock

    def _date_env(self) -> dict:
        stamp = self.clock.isoformat()
        return {"GIT_AUTHOR_DATE": stamp, "GIT_COMMITTER_DATE": stamp}

    # ----- repos ----------------------------------------------------------------------------------------------

    def _create_repo(self, name: str, main_writers: list[str], branch_writers: list[str], deploy_keys=()):
        # Numbered, because a renamed repo keeps its directory while a new repo takes its old name.
        path = self.root / "github" / f"{len(self.policies) + 1}-{name.replace('/', '__')}.git"
        path.mkdir(parents=True)
        _git(path, "init", "-q", "--bare", "-b", "main")
        _git(path, "config", "uploadpack.allowAnySHA1InWant", "true")
        hook = path / "hooks" / "pre-receive"
        hook.write_text(f'#!/bin/sh\nexec "{sys.executable}" "{HERE / "hook.py"}"\n')
        hook.chmod(0o755)
        self.repos[name] = path
        self.policies[name] = {
            "repo": name,
            "main_writers": main_writers,
            "branch_writers": branch_writers,
            "deploy_keys": list(deploy_keys),
        }
        self._write_policy(name)
        self.vars.setdefault(name, {})
        self.environments.setdefault(name, {})

    def _write_policy(self, name: str):
        (self.repos[name] / "sim-policy.json").write_text(json.dumps(self.policies[name]))

    def rename(self, old: str, new: str):
        """GitHub's rename: settings, secrets, variables and environments follow the repo."""
        for registry in (self.repos, self.policies, self.vars, self.environments):
            registry[new] = registry.pop(old)
        self.policies[new]["repo"] = new
        self._write_policy(new)
        self._work = {(r if r != old else new, c): p for (r, c), p in self._work.items()}
        state = self._state()
        for section in ("settings", "labels"):
            if old in state[section]:
                state[section][new] = state[section].pop(old)
        for pr in state["prs"]:
            if pr["repo"] == old:
                pr["repo"] = new
                pr["url"] = pr["url"].replace(old, new)
        self._save_state(state)

    def _workflow_and_script_files(self) -> dict[str, bytes]:
        files = {}
        for name in COPIED_WORKFLOWS:
            files[f".github/workflows/{name}"] = (REPO_ROOT / ".github/workflows" / name).read_bytes()
        for path in sorted(SCRIPTS_DIR.glob("*")):
            if path.is_file():
                files[f".github/scripts/feed_tiers/{path.name}"] = path.read_bytes()
        return files

    def work_clone(self, repo: str, credential: str) -> Path:
        """A working clone that pushes with the given credential, synced to the remote's main."""
        key = (repo, credential)
        if key not in self._work:
            path = self.root / "work" / f"{len(self._work) + 1}-{repo.replace('/', '__')}--{credential.replace(':', '_')}"
            path.mkdir(parents=True)
            _git(path, "init", "-q", "-b", "main")
            _git(path, "config", "user.name", "World")
            _git(path, "config", "user.email", "world@example.com")
            _git(path, "config", "commit.gpgsign", "false")
            _git(path, "remote", "add", "origin", f"file://{self.repos[repo]}")
            self._work[key] = path
        path = self._work[key]
        _git(path, "remote", "set-url", "origin", f"file://{self.repos[repo]}")
        _git(path, "config", "remote.origin.receivepack", f"env SIM_CREDENTIAL={shlex.quote(credential)} git-receive-pack")
        _git(path, "fetch", "-q", "--prune", "origin", "+refs/heads/*:refs/remotes/origin/*")
        if _git(path, "rev-parse", "--verify", "-q", "refs/remotes/origin/main", check=False).strip():
            _git(path, "checkout", "-q", "-B", "main", "refs/remotes/origin/main")
            _git(path, "clean", "-qfdx")
        return path

    def _write_files(self, path: Path, files: dict[str, bytes | str | None]):
        for name, content in files.items():
            target = path / name
            if content is None:
                if target.exists() or target.is_symlink():
                    if target.is_dir() and not target.is_symlink():
                        shutil.rmtree(target)
                    else:
                        target.unlink()
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content.encode() if isinstance(content, str) else content)

    def commit(self, repo, files, message="change", credential="admin", author=("Admin", "admin@example.com"), ref="main") -> str:
        """Commits straight to a branch (default main) with the given credential: setup, bypasses and tampering."""
        path = self.work_clone(repo, credential)
        if ref != "main":
            _git(path, "checkout", "-q", "-B", ref, "refs/remotes/origin/main")
        self._write_files(path, files)
        _git(path, "add", "-A")
        env = {**self._date_env(), "GIT_AUTHOR_NAME": author[0], "GIT_AUTHOR_EMAIL": author[1]}
        _git(path, "commit", "-q", "--allow-empty", "-m", message, env=env)
        result = subprocess.run(["git", "push", "-q", "origin", f"HEAD:refs/heads/{ref}"], cwd=path, capture_output=True)
        if result.returncode != 0:
            raise PermissionError(result.stderr.decode())
        return _git(path, "rev-parse", "HEAD").strip()

    def head(self, repo: str, ref: str = "main") -> str:
        return _git(self.repos[repo], "rev-parse", f"refs/heads/{ref}").strip()

    def files(self, repo: str, prefix: str = "detection-rules", ref: str = "main") -> dict[str, bytes]:
        bare = self.repos[repo]
        pathspec = ["--", f"{prefix}/"] if prefix else []
        names = _git(bare, "ls-tree", "-r", "-z", "--name-only", f"refs/heads/{ref}", *pathspec).split("\0")
        return {n: subprocess.run(["git", "show", f"refs/heads/{ref}:{n}"], cwd=bare, capture_output=True, check=True).stdout for n in names if n}

    def log(self, repo: str, ref: str = "main", fmt: str = "%H") -> list[str]:
        return [line for line in _git(self.repos[repo], "log", f"--format={fmt}", f"refs/heads/{ref}").split("\n") if line]

    def messages(self, repo: str, ref: str = "main") -> list[str]:
        """Full commit messages, newest first."""
        out = _git(self.repos[repo], "log", "-z", "--format=%B", f"refs/heads/{ref}")
        return [m.strip() for m in out.split("\0") if m.strip()]

    # ----- state shared with fake gh --------------------------------------------------------------------------

    def _state(self) -> dict:
        return json.loads(self.state_file.read_text())

    def _save_state(self, state: dict):
        self.state_file.write_text(json.dumps(state, indent=2))

    def prs(self, repo: str = PRIVATE, state: str | None = None) -> list[dict]:
        return [p for p in self._state()["prs"] if p["repo"] == repo and (state is None or p["state"] == state)]

    def pr(self, number: int) -> dict:
        return next(p for p in self._state()["prs"] if p["number"] == number)

    def _update_pr(self, number: int, **changes):
        state = self._state()
        for pr in state["prs"]:
            if pr["number"] == number:
                pr.update(changes)
        self._save_state(state)

    def set_actions_can_create_prs(self, repo: str, allowed: bool = True):
        state = self._state()
        state["settings"].setdefault(repo, {})["actions_can_create_prs"] = allowed
        self._save_state(state)

    def create_label(self, repo: str, label: str):
        state = self._state()
        state["labels"].setdefault(repo, []).append(label)
        self._save_state(state)

    def dispatches(self, repo: str = PRIVATE) -> list[dict]:
        return [d for d in self._state()["dispatches"] if d["repo"] == repo]

    # ----- the cutover ----------------------------------------------------------------------------------------

    def cutover(self, deploy_key: str = MIRROR_KEY, secret: str | None = MIRROR_KEY):
        """The rollout's cutover, in order: rename, make the new public repo from the same history, remove the old
        workflows from it in a bootstrap commit, then the deploy key, environment secret and settings."""
        self.rename(OLD_NAME, PRIVATE)
        self.policies[PRIVATE]["branch_writers"] = ["dev", "token", "merge", "admin"]
        self._write_policy(PRIVATE)

        self._create_repo(PUBLIC, main_writers=["deploy-key", "admin"], branch_writers=["admin"], deploy_keys=[deploy_key])
        private_main = self.head(PRIVATE)
        admin = self.work_clone(PRIVATE, "admin")
        _git(admin, "push", "-q", f"file://{self.repos[PUBLIC]}", f"{private_main}:refs/heads/main", env={"SIM_CREDENTIAL": "admin"})
        assert self.head(PUBLIC) == private_main
        self.commit(
            PUBLIC,
            {".github": None, "README.md": "Detection rules. History before the cutover isn't public.\n"},
            message="Set up the public mirror",
        )

        if secret is not None:
            self.environments[PRIVATE]["public-mirror"] = {"PUBLIC_MIRROR_DEPLOY_KEY": secret}
        self.set_actions_can_create_prs(PRIVATE)
        self.create_label(PRIVATE, "auto-promote")

    # ----- PRs and the merge queue ----------------------------------------------------------------------------

    def open_pr(self, files: dict, title: str = "Change rules", author=("Dev", "dev@example.com"), branch: str | None = None, repo: str = PRIVATE) -> int:
        """A person opens a PR from a branch off main. pull_request workflows run on it."""
        state = self._state()
        number = state["next_number"]
        branch = branch or f"dev/pr-{number}"
        credential = f"dev:{author[0]}"
        path = self.work_clone(repo, credential)
        _git(path, "checkout", "-q", "-B", branch, "refs/remotes/origin/main")
        self._write_files(path, files)
        _git(path, "add", "-A")
        _git(path, "commit", "-q", "--allow-empty", "-m", title, env={**self._date_env(), "GIT_AUTHOR_NAME": author[0], "GIT_AUTHOR_EMAIL": author[1]})
        _git(path, "push", "-q", "-f", "origin", f"HEAD:refs/heads/{branch}")

        state = self._state()
        state["next_number"] = number + 1
        state["prs"].append(
            {"number": number, "repo": repo, "url": f"https://github.com/{repo}/pull/{number}", "head": branch, "base": "main",
             "title": title, "body": "", "labels": [], "state": "open", "opened_by": author[0]}
        )
        self._save_state(state)
        self._run_pull_request(number)
        return number

    def push_to_pr(self, number: int, files: dict, author=("Dev", "dev@example.com")):
        """Another commit on a PR's branch, by a person, so pull_request workflows run again."""
        pr = self.pr(number)
        path = self.work_clone(pr["repo"], f"dev:{author[0]}")
        _git(path, "checkout", "-q", "-B", pr["head"], f"refs/remotes/origin/{pr['head']}")
        self._write_files(path, files)
        _git(path, "add", "-A")
        _git(path, "commit", "-q", "--allow-empty", "-m", "update", env=self._date_env())
        _git(path, "push", "-q", "origin", f"HEAD:refs/heads/{pr['head']}")
        self._run_pull_request(number)

    def _merge_ref(self, number: int) -> tuple[str, str, str]:
        """GitHub's refs/pull/N/merge: the PR head merged into the current base. Returns (merge, base, head)."""
        pr = self.pr(number)
        path = self.work_clone(pr["repo"], "merge")
        base = _git(path, "rev-parse", "refs/remotes/origin/main").strip()
        head = _git(path, "rev-parse", f"refs/remotes/origin/{pr['head']}").strip()
        _git(path, "checkout", "-q", "--detach", base)
        _git(path, "merge", "-q", "--no-ff", "--no-edit", head, env=self._date_env())
        merge = _git(path, "rev-parse", "HEAD").strip()
        _git(path, "push", "-q", "-f", "origin", f"{merge}:refs/pull/{number}/merge", f"{head}:refs/pull/{number}/head")
        return merge, base, head

    def _run_pull_request(self, number: int):
        merge, base, head = self._merge_ref(number)
        pr = self.pr(number)
        payload = {"pull_request": {"number": number, "head": {"sha": head, "ref": pr["head"]}, "base": {"sha": base, "ref": "main"}}}
        for workflow in self._workflows_for(pr["repo"], merge, "pull_request"):
            self.run_workflow(workflow, "pull_request", repo=pr["repo"], ref=f"refs/pull/{number}/merge", sha=merge, payload=payload, check_sha=head)

    def _workflows_for(self, repo: str, sha: str, event: str) -> list[str]:
        out = []
        for name in SIMULATED_WORKFLOWS:
            text = _git(self.repos[repo], "show", f"{sha}:.github/workflows/{name}", check=False)
            if text and event in _triggers(yaml.safe_load(text)):
                out.append(name)
        return out

    def checks_passed(self, sha: str) -> bool:
        return all(self.checks.get(sha, {}).get(name) == "success" for name in REQUIRED_CHECKS)

    def merge_pr(self, number: int, run_push_workflows: bool = True) -> str:
        """Adds the PR to the merge queue: required checks must have passed on its head, then on the squashed
        commit (merge_group). On success main moves to that commit and push workflows run."""
        pr = self.pr(number)
        if pr["state"] != "open":
            raise MergeBlocked(f"PR {number} is {pr['state']}")
        repo = pr["repo"]
        path = self.work_clone(repo, "merge")
        head = _git(path, "rev-parse", f"refs/remotes/origin/{pr['head']}").strip()
        if not self.checks_passed(head):
            raise MergeBlocked(f"PR {number}: required checks haven't passed on {head[:12]}: {self.checks.get(head)}")

        base = self.head(repo)
        author = _git(path, "log", "-1", "--format=%an%x00%ae", head).strip().split("\0")
        _git(path, "checkout", "-q", "-B", "queue", base)
        merged = subprocess.run(["git", "merge", "--squash", head], cwd=path, capture_output=True)
        if merged.returncode != 0:
            _git(path, "merge", "--abort", check=False)
            _git(path, "reset", "-q", "--hard", base)
            raise MergeBlocked(f"PR {number} conflicts with main:\n{merged.stdout.decode()}{merged.stderr.decode()}")
        env = {**self._date_env(), "GIT_AUTHOR_NAME": author[0], "GIT_AUTHOR_EMAIL": author[1],
               "GIT_COMMITTER_NAME": SIM_GITHUB[0], "GIT_COMMITTER_EMAIL": SIM_GITHUB[1]}
        _git(path, "commit", "-q", "--allow-empty", "-m", f"{pr['title']} (#{number})", env=env)
        queued = _git(path, "rev-parse", "HEAD").strip()
        queue_ref = f"refs/heads/gh-readonly-queue/main/pr-{number}-{base[:8]}"
        _git(path, "push", "-q", "origin", f"{queued}:{queue_ref}")

        payload = {"merge_group": {"base_sha": base, "head_sha": queued, "head_ref": queue_ref}}
        for workflow in self._workflows_for(repo, queued, "merge_group"):
            self.run_workflow(workflow, "merge_group", repo=repo, ref=queue_ref, sha=queued, payload=payload)
        try:
            if not self.checks_passed(queued):
                raise MergeBlocked(f"PR {number}: required checks failed in the merge queue: {self.checks.get(queued)}")
            _git(path, "push", "-q", "origin", f"{queued}:refs/heads/main")
        finally:
            _git(path, "push", "-q", "origin", f":{queue_ref}")

        self._update_pr(number, state="merged", merge_commit=queued)
        if run_push_workflows:
            self.on_push(repo)
        return queued

    def close_pr(self, number: int):
        self._update_pr(number, state="closed")

    def on_push(self, repo: str = PRIVATE) -> list[RunResult]:
        """The push to main's workflows, as GitHub would start them after a merge."""
        sha = self.head(repo)
        return [
            self.run_workflow(w, "push", repo=repo, ref="refs/heads/main", sha=sha)
            for w in self._workflows_for(repo, sha, "push")
        ]

    def run_dispatches(self, repo: str = PRIVATE) -> list[RunResult]:
        """Runs workflow_dispatch events that gh queued. rule-validate isn't simulated: its run records success."""
        state = self._state()
        pending = [d for d in state["dispatches"] if d["repo"] == repo and not d["handled"]]
        for d in pending:
            d["handled"] = True
        self._save_state(state)
        results = []
        for d in pending:
            sha = self.head(repo, d["ref"])
            if d["workflow"] in SIMULATED_WORKFLOWS:
                results.append(self.run_workflow(d["workflow"], "workflow_dispatch", repo=repo, ref=f"refs/heads/{d['ref']}", sha=sha))
            else:
                self.checks.setdefault(sha, {})[d["workflow"].removesuffix(".yml")] = "success"
        return results

    # ----- shorthands -----------------------------------------------------------------------------------------

    def sync(self, event: str = "schedule", **inputs) -> RunResult:
        return self.run_workflow("sync-public.yml", event, inputs=inputs or None)

    def promote(self, dry_run: bool = False, as_of: datetime | None = None) -> RunResult:
        """A scheduled promote run, at the world's clock (through the as_of input, since real cron uses real time)."""
        inputs = {"as_of": (as_of or self.clock).isoformat(), "dry_run": dry_run}
        result = self.run_workflow("promote-delayed.yml", "workflow_dispatch", inputs=inputs)
        if result.ok:
            self.run_dispatches()
        return result

    # ----- running workflows ----------------------------------------------------------------------------------

    def run_workflow(
        self,
        workflow: str,
        event: str,
        repo: str = PRIVATE,
        ref: str = "refs/heads/main",
        sha: str | None = None,
        inputs: dict | None = None,
        payload: dict | None = None,
        check_sha: str | None = None,
        before_step=None,
    ) -> RunResult:
        sha = sha or _git(self.repos[repo], "rev-parse", ref).strip()
        definition = yaml.safe_load(_git(self.repos[repo], "show", f"{sha}:.github/workflows/{workflow}"))
        triggers = _triggers(definition)
        if event not in triggers:
            raise AssertionError(f"{workflow} isn't triggered by {event}")
        if event == "push":
            branches = (triggers["push"] or {}).get("branches")
            if branches and ref.removeprefix("refs/heads/") not in branches:
                raise AssertionError(f"{workflow} doesn't run on pushes to {ref}")

        resolved_inputs = {}
        if event == "workflow_dispatch":
            declared = (triggers["workflow_dispatch"] or {}).get("inputs") or {}
            for name, spec in declared.items():
                value = (inputs or {}).get(name, spec.get("default"))
                if spec.get("type") == "boolean" and value is not None:
                    value = value is True or value == "true"
                resolved_inputs[name] = value
            unknown = set(inputs or {}) - set(declared)
            if unknown:
                raise AssertionError(f"{workflow} has no inputs {unknown}")

        (job_id, job), = definition["jobs"].items()
        permissions = job.get("permissions", definition.get("permissions", {}))
        perms = ",".join(f"{k}={v}" for k, v in sorted((permissions or {}).items()))
        token = f"token:{repo}:{perms}"
        self._run_count += 1
        workspace = self.root / "runs" / f"{self._run_count:03}-{workflow}-{event}" / "workspace"
        workspace.mkdir(parents=True)

        context = {
            "github": {
                "repository": repo,
                "repository_owner": repo.split("/")[0],
                "sha": sha,
                "ref": ref,
                "ref_name": ref.split("/", 2)[-1],
                "event_name": event,
                "event": {**(payload or {}), **({"inputs": resolved_inputs} if event == "workflow_dispatch" else {})},
                "token": token,
                "workspace": str(workspace),
                "run_id": str(self._run_count),
            },
            "inputs": resolved_inputs,
            "vars": dict(self.vars[repo]),
            "secrets": {},
            "env": {},
            "steps": {},
            "runner": {"temp": str(workspace.parent / "tmp"), "os": "Linux"},
        }
        result = RunResult(workflow, event, "success", sha=sha)
        check_name = job.get("name", job_id)

        if not expressions.condition(job.get("if"), context, "success"):
            result.conclusion = "skipped"
            self.runs.append(result)
            return result

        environment = job.get("environment")
        if environment:
            env_name = environment if isinstance(environment, str) else environment["name"]
            if ref != "refs/heads/main":
                result.conclusion = "failure"
                result.reason = f"Branch {ref} is not allowed to deploy to {env_name} due to environment protection rules."
                self._record(result, check_sha or sha, check_name)
                return result
            context["secrets"] = dict(self.environments[repo].get(env_name, {}))

        context["env"] = {k: expressions.render(str(v), context) for k, v in {**definition.get("env", {}), **job.get("env", {})}.items()}
        defaults = (job.get("defaults") or definition.get("defaults") or {}).get("run", {})
        (workspace.parent / "tmp").mkdir()

        status = "success"
        for index, step in enumerate(job["steps"]):
            name = step.get("name") or step.get("uses") or step.get("run", "").split("\n")[0]
            if not expressions.condition(step.get("if"), context, status):
                result.steps.append(StepResult(name, "skipped"))
                continue
            if before_step:
                before_step(name, self)
            step_result = self._run_step(step, name, context, workspace, repo, token, defaults, index)
            result.steps.append(step_result)
            if step.get("id"):
                context["steps"][step["id"]] = {"outputs": step_result.outputs, "outcome": step_result.outcome}
            if step_result.outcome == "failure":
                status = "failure"

        result.conclusion = status
        self._record(result, check_sha or sha, check_name)
        return result

    def _record(self, result: RunResult, sha: str, check_name: str):
        self.runs.append(result)
        self.checks.setdefault(sha, {})[check_name] = result.conclusion

    def _run_step(self, step, name, context, workspace, repo, token, defaults, index) -> StepResult:
        with_ = {k: expressions.render(str(v), context) if isinstance(v, str) else v for k, v in (step.get("with") or {}).items()}
        uses = step.get("uses", "")
        if uses.startswith("actions/checkout@"):
            return self._checkout(name, with_, context, workspace, repo, token)
        if uses.startswith("actions/setup-python@"):
            return StepResult(name, "success", "python is already set up")
        if uses:
            return StepResult(name, "failure", f"the simulator doesn't support {uses}")

        script = expressions.render(step["run"], context)
        if script.strip().startswith("pip install"):
            return StepResult(name, "success", "dependencies are already installed")

        output_file = workspace.parent / "tmp" / f"output-{index}"
        output_file.touch()
        summary_file = workspace.parent / "tmp" / "summary.md"
        env = {
            **os.environ,
            **self._date_env(),
            "PATH": f"{self.bin}{os.pathsep}{os.environ['PATH']}",
            "GITHUB_ACTIONS": "true",
            "CI": "true",
            "GITHUB_REPOSITORY": repo,
            "GITHUB_SHA": context["github"]["sha"],
            "GITHUB_REF": context["github"]["ref"],
            "GITHUB_EVENT_NAME": context["github"]["event_name"],
            "GITHUB_WORKSPACE": str(workspace),
            "GITHUB_OUTPUT": str(output_file),
            "GITHUB_STEP_SUMMARY": str(summary_file),
            "RUNNER_TEMP": context["runner"]["temp"],
            "FAKE_GH_STATE": str(self.state_file),
            "FAKE_GH_REPOS": json.dumps({k: str(v) for k, v in self.repos.items()}),
            **context["env"],
            **{k: expressions.render(str(v), context) for k, v in (step.get("env") or {}).items()},
        }
        cwd = workspace / (step.get("working-directory") or defaults.get("working-directory") or "")
        proc = subprocess.run(["bash", "--noprofile", "--norc", "-eo", "pipefail", "-c", script], cwd=cwd, env=env, capture_output=True, text=True)
        outputs = _parse_outputs(output_file.read_text())
        return StepResult(name, "success" if proc.returncode == 0 else "failure", proc.stdout + proc.stderr, outputs)

    def _checkout(self, name, with_, context, workspace, workflow_repo, token) -> StepResult:
        repo = with_.get("repository") or workflow_repo
        if repo not in self.repos:
            return StepResult(name, "failure", f"Repository not found: {repo}")
        target = (workspace / (with_.get("path") or "")).resolve()
        depth = int(with_.get("fetch-depth", 1))
        ssh_key = with_.get("ssh-key") or ""
        persist = with_.get("persist-credentials", True) not in (False, "false")
        if ssh_key:
            credential = f"deploy-key:{ssh_key}"
        else:
            credential = token

        github = context["github"]
        ref = with_.get("ref") or ""
        if not ref:
            if repo != workflow_repo:
                ref = "main"
            elif github["event_name"] in ("pull_request", "push", "schedule", "merge_group"):
                ref = github["sha"] if github["event_name"] != "pull_request" else github["ref"]
            else:
                ref = github["ref"]

        log = []
        target.mkdir(parents=True, exist_ok=True)
        url = f"file://{self.repos[repo]}"
        _git(target, "init", "-q", "-b", "main")
        _git(target, "remote", "add", "origin", url)
        _git(target, "config", "commit.gpgsign", "false")
        depth_args = [] if depth == 0 else [f"--depth={depth}"]
        if depth == 0:
            _git(target, "fetch", "-q", "--prune", "--tags", "origin", "+refs/heads/*:refs/remotes/origin/*")

        branch = ref.removeprefix("refs/heads/") if not ref.startswith("refs/pull/") and not _is_sha(ref) else None
        if branch:
            fetched = subprocess.run(["git", "fetch", "-q", *depth_args, "origin", f"+refs/heads/{branch}:refs/remotes/origin/{branch}"], cwd=target, capture_output=True, text=True)
            if fetched.returncode != 0:
                return StepResult(name, "failure", f"couldn't fetch {branch}: {fetched.stderr}")
            _git(target, "checkout", "-q", "-B", branch, f"refs/remotes/origin/{branch}")
            log.append(f"checked out {repo}@{branch}")
        else:
            fetched = subprocess.run(["git", "fetch", "-q", *depth_args, "origin", ref], cwd=target, capture_output=True, text=True)
            if fetched.returncode != 0:
                return StepResult(name, "failure", f"couldn't fetch {ref}: {fetched.stderr}")
            _git(target, "checkout", "-q", "--detach", "FETCH_HEAD")
            log.append(f"checked out {repo}@{ref} (detached)")

        if persist:
            _git(target, "config", "remote.origin.receivepack", f"env SIM_CREDENTIAL={shlex.quote(credential)} git-receive-pack")
        return StepResult(name, "success", "\n".join(log))


def _triggers(definition: dict) -> dict:
    triggers = definition.get(True, definition.get("on"))
    if isinstance(triggers, str):
        return {triggers: None}
    if isinstance(triggers, list):
        return {t: None for t in triggers}
    return triggers


def _is_sha(ref: str) -> bool:
    return len(ref) == 40 and all(c in "0123456789abcdef" for c in ref)


def _parse_outputs(text: str) -> dict:
    outputs, lines, i = {}, text.splitlines(), 0
    while i < len(lines):
        line = lines[i]
        if "<<" in line and "=" not in line.split("<<")[0]:
            key, delimiter = line.split("<<", 1)
            value = []
            i += 1
            while lines[i] != delimiter:
                value.append(lines[i])
                i += 1
            outputs[key] = "\n".join(value)
        elif "=" in line:
            key, value = line.split("=", 1)
            outputs[key] = value
        i += 1
    return outputs
