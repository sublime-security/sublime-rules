"""pre-receive hook for the simulated GitHub repos: who may push to which ref.

The pusher's credential arrives in SIM_CREDENTIAL (set through remote.origin.receivepack by the simulated
checkout). The repo's rules are in sim-policy.json next to the hook's repo:

    {"repo": "owner/name", "main_writers": [...], "branch_writers": [...], "deploy_keys": [...]}

Credentials:
    admin                         setup and tampering in tests
    merge                         GitHub itself, merging a PR or running the merge queue
    dev:<name>                    a person pushing a branch
    token:<repo>:<perm>,<perm>    a workflow's GITHUB_TOKEN, e.g. token:o/r:contents=write
    deploy-key:<key>              an SSH deploy key; only valid where it's registered with write access
"""

import json
import os
import sys


def deny(reason):
    print(f"sim: {reason}", file=sys.stderr)
    sys.exit(1)


def main():
    with open(os.path.join(os.getcwd(), "sim-policy.json")) as f:
        policy = json.load(f)
    credential = os.environ.get("SIM_CREDENTIAL", "")
    if not credential:
        deny("authentication required (no credential)")

    kind, _, rest = credential.partition(":")
    if kind == "token":
        repo, _, perms = rest.partition(":")
        if repo != policy["repo"]:
            deny(f"a GITHUB_TOKEN for {repo} can't push to {policy['repo']}")
        if "contents=write" not in perms.split(","):
            deny("the GITHUB_TOKEN doesn't have contents: write")
    elif kind == "deploy-key":
        if rest not in policy.get("deploy_keys", []):
            deny("that deploy key isn't registered with write access on this repo")
    elif kind not in ("admin", "merge", "dev"):
        deny(f"unknown credential {credential!r}")

    for line in sys.stdin:
        _, _, ref = line.split()
        writers = policy["main_writers"] if ref == "refs/heads/main" else policy["branch_writers"]
        if kind not in writers:
            deny(f"{kind} may not update {ref} (allowed: {', '.join(writers)})")


if __name__ == "__main__":
    main()
