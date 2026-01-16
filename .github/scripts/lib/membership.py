"""
GitHub organization membership and PR checks.
"""
import sys


def is_user_in_org(session, username, org_name, cache=None):
    """
    Check if a user is a member of a specific organization.

    Args:
        session: GitHub API session
        username (str): GitHub username
        org_name (str): Organization name
        cache (PRCache, optional): Cache instance to use

    Returns:
        bool: True if user is a member, False otherwise
    """
    if cache:
        return cache.is_user_in_org(session, username, org_name)

    url = f'https://api.github.com/orgs/{org_name}/members/{username}'
    try:
        response = session.get(url)
        # 404 is expected when user is not in org, so handle it separately
        if response.status_code == 404:
            return False
        response.raise_for_status()
        return response.status_code == 204
    except Exception as e:
        print(f"Error checking organization membership for {username} in {org_name}: {e}")
        print("Failed to get valid response after retries. Exiting script.")
        sys.exit(1)


def has_trigger_comment(session, repo_owner, repo_name, pr_number, org_name, trigger_comment, cache=None):
    """
    Check if a PR has a comment with the trigger text from a member of the specified org.

    Args:
        session: GitHub API session
        repo_owner (str): Repository owner
        repo_name (str): Repository name
        pr_number (int): Pull request number
        org_name (str): Organization name to filter commenters
        trigger_comment (str): Comment text to look for
        cache (PRCache, optional): Cache instance to use

    Returns:
        bool: True if a matching comment is found, False otherwise
    """
    if cache:
        comments = cache.get_comments(session, repo_owner, repo_name, pr_number)
    else:
        url = f'https://api.github.com/repos/{repo_owner}/{repo_name}/issues/{pr_number}/comments'
        response = session.get(url)
        response.raise_for_status()
        comments = response.json()

    for comment in comments:
        # Check if comment contains the trigger and commenter is in the organization
        if trigger_comment in comment['body']:
            commenter = comment['user']['login']
            if is_user_in_org(session, commenter, org_name, cache=cache):
                print(f"\tPR #{pr_number}: Found trigger comment from {commenter} ({org_name} member)")
                return True
            print(f"\tPR #{pr_number}: Found trigger comment from {commenter} (not a {org_name} member, ignoring)")

    return False


def has_required_action_completed(session, repo_owner, repo_name, pr_sha, action_name, required_status):
    """
    Check if a required GitHub Actions workflow has completed with the expected status for a PR.
    Uses the GitHub Checks API to poll for check results.

    Args:
        session: GitHub API session
        repo_owner (str): Repository owner
        repo_name (str): Repository name
        pr_sha (str): SHA of the PR head commit
        action_name (str): Name of the action/check to look for
        required_status (str): Required status (success, failure, etc.)

    Returns:
        bool: True if the action has completed with the required status, False otherwise
    """
    # Use the GitHub Checks API to get all check runs for this commit
    url = f'https://api.github.com/repos/{repo_owner}/{repo_name}/commits/{pr_sha}/check-runs'
    custom_headers = {'Accept': 'application/vnd.github.v3+json'}

    # Temporarily update session headers for this request
    original_accept = session.headers.get('Accept')
    session.headers.update(custom_headers)

    try:
        response = session.get(url)
        response.raise_for_status()
    except Exception as e:
        print(f"\tError checking action status: {e}")
        print("Failed to get valid response after retries. Exiting script.")
        sys.exit(1)
    finally:
        # Restore original Accept header
        session.headers['Accept'] = original_accept

    check_runs = response.json()

    if 'check_runs' not in check_runs or len(check_runs['check_runs']) == 0:
        print(f"\tNo check runs found for commit {pr_sha}")
        return False

    # Look for the specific action by name
    for check in check_runs['check_runs']:
        check_name = check['name']
        check_conclusion = check['conclusion']
        check_status = check['status']

        if action_name.lower() in check_name.lower():

            # Check if the action is complete
            if check_status != 'completed':
                print(f"\tCheck '{check_name}' is still in progress (status: {check_status})")
                return False

            # Check if the action has the required conclusion
            if check_conclusion == required_status:
                return True
            else:
                print(f"\tCheck '{check_name}' has conclusion '{check_conclusion}', expected '{required_status}'")
                return False

    print(f"\tNo check matching '{action_name}' found")
    return False
