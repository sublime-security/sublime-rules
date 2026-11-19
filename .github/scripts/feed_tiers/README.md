# Feed tiers

Scripts for keeping the private `sublime-rules-enterprise` repo and the public `sublime-rules` mirror in sync. A
rule's tier is its top-level `feed_tier` key:

| `feed_tier` | Public repo |
|---|---|
| `core` | synced on every merge |
| `core_with_delay`, or no `feed_tier` key | private until `promote.py` opens a PR changing it to `core`, 90 days after it became `core_with_delay` |
| `enterprise_only` | never |

No key means `core_with_delay`, so forgetting it can't publish a rule early. Rules from before tiers get an explicit
`feed_tier: core` from `stamp_core.py`, once, before the sync is turned on.

The 90 days start when a rule becomes `core_with_delay`: when it merges that way, or when another tier changes to it.
Edits don't move it. Changing to `enterprise_only` and back starts it again (`gitdates.py`).

The sync manages the folders the platform's feeds read (`rules.py`):

| Folder | Tier |
|---|---|
| `detection-rules/`, `dlp-rules/`, `automations/`, `exclusions/` | `feed_tier:` key, as above |
| `yara/*.yar` | `feed_tier = "<tier>"` in each YARA rule's `meta:`; each rule has its own tier |
| `insights/`, and files in `yara/` that aren't `.yar` | none: always public |

Everything else in the public repo (`discovery-rules/`, `emls/`, the README, ...) is left alone.

A `.yar` file whose rules are all `core` is published as it is. One with some `core` rules is published as just those
rules, line for line, after an `import` for each module they use; comments and everything else between rules are left
out, since they could be about a rule that isn't public (comments inside a `core` rule are part of it, and are published). So in such a file, a `core` rule can't use a rule that isn't
`core` (by name or with a rule set like `any of (abc*)`), there can't be global rules or `include` lines, and each rule
must start and end on lines of its own. Tier-check and the sync fail on any of these. YARA rule names must be unique
across `yara/`, since a rule's tier history and promotion follow its name.

| Script | Run by | Does |
|---|---|---|
| `sync.py` | `sync-public.yml`, on push to main and hourly | Makes the public repo's managed folders exactly the private public-tier rules, as one commit. All or nothing: any unparseable rule, unknown tier, duplicate id or demotion fails the run and changes nothing. |
| `guard.py` | `sync-public.yml`, before the push | Re-checks the result independently: fails if any rule in the managed folders isn't public. YARA files are read by both plyara and libyara (`yara-python`), which must agree. |
| `promote.py` | `promote-delayed.yml`, hourly | Opens a one-line PR for each `core_with_delay` rule that's due (each YARA rule on its own), and starts its required checks. |
| `tier_check.py` | `tier-check.yml`, on PRs and the merge queue | Blocks unknown tiers, YARA files that can't be split, reused ids and YARA rule names, demotions (including deleting a `feed_tier: core` line; a YARA rule is matched by name), and (until `NON_CORE_TIERS_ENABLED`) any added or changed rule that isn't `core`. |
| `default_tier.py` | `default-tier.yml`, on PRs from this repo's branches once `NON_CORE_TIERS_ENABLED` | Adds `feed_tier: core_with_delay` to any added or changed rule with no key, as a commit on the PR branch, comments on the PR, and starts its required checks. The tier doesn't change: it only makes the default visible. A rule that's `core` on the base branch and lost its key is a demotion, so it's left alone for tier-check to block (and named in the comment and job summary). |
| `stamp_core.py` | by hand, once | Adds `feed_tier: core` to every rule with a tier but no key, in the working tree. |

`sync-public.yml` and `promote-delayed.yml` only run in `sublime-security/sublime-rules-enterprise`, so they do nothing
until the rename.

## Tests

```bash
pip install -r requirements-dev.txt
python -m pytest -n auto
```

- `test_rules.py`, `test_project.py`: parsing tiers and the projection, as pure functions.
- `test_sync.py`, `test_promote.py`, `test_tier_check.py`, `test_default_tier.py`: each script against real temporary git repos.
- `test_folders.py`: the folders beyond `detection-rules/` (YARA tiers, always-public files) through every script.
- `test_yara_rules.py`: YARA files whose rules have different tiers, through every script.
- `test_property.py`: Hypothesis generates random histories of rule changes, tampering and syncs, and checks the
  invariants after each sync.
- `test_e2e.py`: the real workflow files run by a simulated GitHub (`tests/gha/`), from today's repo through the
  cutover, PRs, the merge queue, promotions and failures. It enforces branch protection, the public repo's ruleset,
  deploy keys, token permissions, environments and required checks, so a workflow that relies on more access than
  it has fails here.
- `test_simulator.py`, `test_workflows.py`: the simulator's own rules, and static checks on the workflow files.
