"""A stand-in for the gh CLI that reads and writes the simulated GitHub's state.

Supports only what promote.py runs, and enforces what real GitHub would:
- GH_TOKEN must carry the needed permission (pull-requests: write, actions: write);
- creating a PR needs the "Allow GitHub Actions to create pull requests" setting, an existing head branch and an
  existing label, and fails if a PR from that branch is already open;
- a workflow can only be dispatched if it exists at that ref and has a workflow_dispatch trigger.

Environment: FAKE_GH_STATE (state JSON), FAKE_GH_REPOS (JSON map of repo name to bare repo path), GH_TOKEN.
"""

import argparse
import json
import os
import subprocess
import sys

import yaml


def fail(message):
    print(message, file=sys.stderr)
    sys.exit(1)


def load():
    with open(os.environ["FAKE_GH_STATE"]) as f:
        return json.load(f)


def save(state):
    with open(os.environ["FAKE_GH_STATE"], "w") as f:
        json.dump(state, f, indent=2)


def token_permissions(repo):
    token = os.environ.get("GH_TOKEN", "")
    kind, _, rest = token.partition(":")
    token_repo, _, perms = rest.partition(":")
    if kind != "token":
        fail("gh: To use GitHub CLI in a GitHub Actions workflow, set the GH_TOKEN environment variable.")
    if token_repo != repo:
        fail(f"HTTP 403: the GITHUB_TOKEN for {token_repo} can't act on {repo}")
    return set(perms.split(","))


def bare(repo):
    repos = json.loads(os.environ["FAKE_GH_REPOS"])
    if repo not in repos:
        fail(f"HTTP 404: Could not resolve to a Repository with the name '{repo}'.")
    return repos[repo]


def git(path, *args):
    return subprocess.run(["git", "-C", path, *args], capture_output=True, text=True)


def pr_list(args):
    token_permissions(args.repo)
    state = load()
    prs = [
        {"url": pr["url"], "number": pr["number"]}
        for pr in state["prs"]
        if pr["repo"] == args.repo and pr["head"] == args.head and (args.state == "all" or pr["state"] == args.state)
    ]
    print(json.dumps([{k: pr[k] for k in args.json.split(",")} for pr in prs]))


def pr_create(args):
    perms = token_permissions(args.repo)
    if "pull-requests=write" not in perms:
        fail("HTTP 403: Resource not accessible by integration (createPullRequest)")
    state = load()
    if not state["settings"].get(args.repo, {}).get("actions_can_create_prs"):
        fail("pull request create failed: GitHub Actions is not permitted to create or approve pull requests.")
    if git(bare(args.repo), "rev-parse", "--verify", f"refs/heads/{args.head}").returncode != 0:
        fail(f"pull request create failed: Head sha can't be blank, Head ref must be a branch ({args.head})")
    for label in args.label or []:
        if label not in state["labels"].get(args.repo, []):
            fail(f"could not add label: '{label}' not found")
    if any(pr["repo"] == args.repo and pr["head"] == args.head and pr["state"] == "open" for pr in state["prs"]):
        fail(f'a pull request for branch "{args.head}" into branch "{args.base}" already exists')
    body = sys.stdin.read() if args.body_file == "-" else open(args.body_file).read()

    number = state["next_number"]
    state["next_number"] += 1
    url = f"https://github.com/{args.repo}/pull/{number}"
    state["prs"].append(
        {
            "number": number,
            "repo": args.repo,
            "url": url,
            "head": args.head,
            "base": args.base,
            "title": args.title,
            "body": body,
            "labels": args.label or [],
            "state": "open",
            "opened_by": "github-actions[bot]",
        }
    )
    save(state)
    print(url)


def workflow_run(args):
    perms = token_permissions(args.repo)
    if "actions=write" not in perms:
        fail("HTTP 403: Resource not accessible by integration (createWorkflowDispatch)")
    shown = git(bare(args.repo), "show", f"refs/heads/{args.ref}:.github/workflows/{args.workflow}")
    if shown.returncode != 0:
        fail(f"could not find any workflows named {args.workflow} at {args.ref}")
    workflow = yaml.safe_load(shown.stdout)
    triggers = workflow.get(True, workflow.get("on"))
    if not (isinstance(triggers, dict) and "workflow_dispatch" in triggers) and triggers != "workflow_dispatch":
        fail(f"HTTP 422: Workflow does not have 'workflow_dispatch' trigger ({args.workflow})")
    state = load()
    state["dispatches"].append({"repo": args.repo, "workflow": args.workflow, "ref": args.ref, "handled": False})
    save(state)
    print(f"Created workflow_dispatch event for {args.workflow} at {args.ref}", file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(prog="gh")
    commands = parser.add_subparsers(dest="group", required=True)

    pr = commands.add_parser("pr").add_subparsers(dest="command", required=True)
    p = pr.add_parser("list")
    p.add_argument("--repo", required=True)
    p.add_argument("--head", required=True)
    p.add_argument("--state", default="open")
    p.add_argument("--json", required=True)
    p.set_defaults(func=pr_list)
    p = pr.add_parser("create")
    p.add_argument("--repo", required=True)
    p.add_argument("--base", required=True)
    p.add_argument("--head", required=True)
    p.add_argument("--title", required=True)
    p.add_argument("--body-file", required=True)
    p.add_argument("--label", action="append")
    p.set_defaults(func=pr_create)

    wf = commands.add_parser("workflow").add_subparsers(dest="command", required=True)
    p = wf.add_parser("run")
    p.add_argument("workflow")
    p.add_argument("--repo", required=True)
    p.add_argument("--ref", required=True)
    p.set_defaults(func=workflow_run)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
