# Feed tiers

Scripts for keeping the private `sublime-rules-enterprise` repo and the public `sublime-rules` mirror in sync. A
rule's tier is its top-level `feed_tier` key:

| `feed_tier` | Public repo |
|---|---|
| absent (rules from before tiers) or `core` | synced on every merge |
| `core_with_delay` | private until `promote.py` opens a PR changing it to `core`, 90 days after it first merged |
| `enterprise_only` | never |

Only `detection-rules/` is mirrored. Everything else in the public repo is left alone.

| Script | Run by | Does |
|---|---|---|
| `sync.py` | `sync-public.yml`, on push to main and hourly | Makes the public `detection-rules/` exactly the private public-tier rules, as one commit. All or nothing: any unparseable rule, unknown tier, duplicate id or demotion fails the run and changes nothing. |
| `guard.py` | `sync-public.yml`, before the push | Re-checks the result independently: fails if any rule in the tree isn't public. |
| `promote.py` | `promote-delayed.yml`, hourly | Opens a one-line PR for each `core_with_delay` rule that's due, and starts its required checks. |
| `tier_check.py` | `tier-check.yml`, on PRs and the merge queue | Blocks unknown tiers, demotions, and (until `NON_CORE_TIERS_ENABLED`) any tier but `core`. |

`sync-public.yml` and `promote-delayed.yml` only run in `sublime-security/sublime-rules-enterprise`, so they do nothing
until the rename.

## Tests

```bash
pip install -r requirements-dev.txt
python -m pytest -n auto
```

- `test_rules.py`, `test_project.py`: parsing tiers and the projection, as pure functions.
- `test_sync.py`, `test_promote.py`, `test_tier_check.py`: each script against real temporary git repos.
- `test_property.py`: Hypothesis generates random histories of rule changes, tampering and syncs, and checks the
  invariants after each sync.
- `test_e2e.py`: the real workflow files run by a simulated GitHub (`tests/gha/`), from today's repo through the
  cutover, PRs, the merge queue, promotions and failures. It enforces branch protection, the public repo's ruleset,
  deploy keys, token permissions, environments and required checks, so a workflow that relies on more access than
  it has fails here.
- `test_simulator.py`, `test_workflows.py`: the simulator's own rules, and static checks on the workflow files.
