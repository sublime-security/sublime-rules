"""
PR comment management functions.
"""
from .constants import (
    AUTHOR_MEMBERSHIP_EXCLUSION_LABEL,
    BULK_PR_LABEL,
    LINK_ANALYSIS_EXCLUSION_LABEL,
    SHARED_SAMPLES_AUTHOR_MEMBERSHIP_EXCLUSION_LABEL,
    SHARED_SAMPLES_BULK_PR_LABEL,
    DEFAULT_COMMENT_TRIGGER,
)


# Marker to identify bot comments for deduplication
COMMENT_MARKER = '<!-- sublime-sync-bot -->'


def has_existing_comment(session, repo_owner, repo_name, pr_number, marker_text):
    """
    Check if a PR already has a comment with the specified marker.

    Args:
        session: GitHub API session
        repo_owner (str): Repository owner
        repo_name (str): Repository name
        pr_number (int): Pull request number
        marker_text (str): Text marker to search for

    Returns:
        bool: True if comment with marker exists, False otherwise
    """
    url = f'https://api.github.com/repos/{repo_owner}/{repo_name}/issues/{pr_number}/comments'
    response = session.get(url)
    response.raise_for_status()
    comments = response.json()

    for comment in comments:
        if marker_text in comment.get('body', ''):
            return True

    return False


def add_pr_comment(session, repo_owner, repo_name, pr_number, body):
    """
    Add a comment to a PR.

    Args:
        session: GitHub API session
        repo_owner (str): Repository owner
        repo_name (str): Repository name
        pr_number (int): Pull request number
        body (str): Comment body text

    Returns:
        bool: True if comment was added successfully, False otherwise
    """
    url = f'https://api.github.com/repos/{repo_owner}/{repo_name}/issues/{pr_number}/comments'
    payload = {'body': body}

    try:
        response = session.post(url, json=payload)
        response.raise_for_status()
        print(f"\tAdded comment to PR #{pr_number}")
        return True
    except Exception as e:
        print(f"\tFailed to add comment to PR #{pr_number}: {e}")
        return False


def generate_exclusion_comment(exclusion_type, org_name=None, max_rules=None, rule_count=None, comment_trigger=None):
    """
    Generate a user-friendly comment explaining why a PR was excluded from syncing.

    Args:
        exclusion_type (str): Type of exclusion (author_membership, bulk_rules, link_analysis)
        org_name (str, optional): Organization name for membership exclusions
        max_rules (int, optional): Max rules limit for bulk exclusions
        rule_count (int, optional): Actual rule count for bulk exclusions
        comment_trigger (str, optional): Comment trigger text

    Returns:
        str: Formatted comment body with marker
    """
    if comment_trigger is None:
        comment_trigger = DEFAULT_COMMENT_TRIGGER

    if exclusion_type == AUTHOR_MEMBERSHIP_EXCLUSION_LABEL:
        body = f"""{COMMENT_MARKER}
### Test Rules Sync - Action Required

This PR was not automatically synced to test-rules because the author is not a member of the `{org_name}` organization.

**To enable syncing**, an organization member can comment `{comment_trigger}` on this PR.

Once triggered, the rules will be synced on the next scheduled run (every 10 minutes).
"""
    elif exclusion_type == BULK_PR_LABEL:
        body = f"""{COMMENT_MARKER}
### Test Rules Sync - Excluded

This PR contains **{rule_count} rules**, which exceeds the maximum of **{max_rules} rules** allowed per PR for automatic syncing.

This limit helps ensure the test-rules environment remains manageable. If you need to test these rules, consider:
- Splitting the PR into smaller PRs with fewer rules
- Contacting Detection Operations to request a manual sync
"""
    elif exclusion_type == SHARED_SAMPLES_AUTHOR_MEMBERSHIP_EXCLUSION_LABEL:
        body = f"""{COMMENT_MARKER}
### Shared Samples Sync - Action Required

This PR was not automatically synced to shared-samples because the author is not a member of the `{org_name}` organization.

**To enable syncing**, an organization member can comment `{comment_trigger}` on this PR.

Once triggered, the rules will be synced on the next scheduled run (every 10 minutes).
"""
    elif exclusion_type == SHARED_SAMPLES_BULK_PR_LABEL:
        body = f"""{COMMENT_MARKER}
### Shared Samples Sync - Excluded

This PR contains **{rule_count} rules**, which exceeds the maximum of **{max_rules} rules** allowed per PR for automatic syncing.

This limit helps ensure the shared-samples environment remains manageable. If you need to test these rules, consider:
- Splitting the PR into smaller PRs with fewer rules
- Contacting Detection Operations to request a manual sync
"""
    elif exclusion_type == LINK_ANALYSIS_EXCLUSION_LABEL:
        body = f"""{COMMENT_MARKER}
### Test Rules Sync - Excluded

This PR contains rules that use `ml.link_analysis`, which is not supported in the test-rules environment.

The `hunting-required` label has been applied. These rules will need to be tested through alternative methods.
"""
    else:
        body = f"""{COMMENT_MARKER}
### Test Rules Sync - Excluded

This PR has been excluded from automatic syncing. Please check the applied labels for more details.
"""

    return body


def post_exclusion_comment_if_needed(session, repo_owner, repo_name, pr_number, exclusion_type, **kwargs):
    """
    Post an exclusion comment to a PR if one doesn't already exist.

    Args:
        session: GitHub API session
        repo_owner (str): Repository owner
        repo_name (str): Repository name
        pr_number (int): Pull request number
        exclusion_type (str): Type of exclusion
        **kwargs: Additional arguments passed to generate_exclusion_comment

    Returns:
        bool: True if comment was added or already exists, False on error
    """
    # Check if we've already commented
    if has_existing_comment(session, repo_owner, repo_name, pr_number, COMMENT_MARKER):
        print(f"\tPR #{pr_number} already has an exclusion comment, skipping")
        return True

    # Generate and post the comment
    body = generate_exclusion_comment(exclusion_type, **kwargs)
    return add_pr_comment(session, repo_owner, repo_name, pr_number, body)
