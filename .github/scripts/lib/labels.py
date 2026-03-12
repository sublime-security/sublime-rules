"""
GitHub label management functions.
"""
import sys


def has_label(session, repo_owner, repo_name, pr_number, label_name):
    """
    Check if a PR has a specific label.

    Args:
        session: GitHub API session
        repo_owner (str): Repository owner
        repo_name (str): Repository name
        pr_number (int): Pull request number
        label_name (str): Label name to check for

    Returns:
        bool: True if PR has the label, False otherwise
    """
    url = f'https://api.github.com/repos/{repo_owner}/{repo_name}/issues/{pr_number}/labels'
    response = session.get(url)
    response.raise_for_status()
    labels = response.json()

    return any(label['name'] == label_name for label in labels)


def apply_label(session, repo_owner, repo_name, pr_number, label_name):
    """
    Apply a label to a PR.

    Args:
        session: GitHub API session
        repo_owner (str): Repository owner
        repo_name (str): Repository name
        pr_number (int): Pull request number
        label_name (str): Label name to apply

    Returns:
        bool: True if label was applied successfully, False otherwise
    """
    url = f'https://api.github.com/repos/{repo_owner}/{repo_name}/issues/{pr_number}/labels'
    payload = {'labels': [label_name]}

    try:
        response = session.post(url, json=payload)
        response.raise_for_status()
        print(f"\tApplied label '{label_name}' to PR #{pr_number}")
        return True
    except Exception as e:
        print(f"\tFailed to apply label '{label_name}' to PR #{pr_number}: {e}")
        print("Failed to get valid response after retries. Exiting script.")
        sys.exit(1)


def remove_label(session, repo_owner, repo_name, pr_number, label_name):
    """
    Remove a label from a PR.

    Args:
        session: GitHub API session
        repo_owner (str): Repository owner
        repo_name (str): Repository name
        pr_number (int): Pull request number
        label_name (str): Label name to remove

    Returns:
        bool: True if label was removed successfully, False otherwise
    """
    url = f'https://api.github.com/repos/{repo_owner}/{repo_name}/issues/{pr_number}/labels/{label_name}'

    try:
        response = session.delete(url)
        if response.status_code == 404:
            print(f"\tLabel '{label_name}' not found on PR #{pr_number}")
            return True  # Consider it successful if the label wasn't there
        response.raise_for_status()
        print(f"\tRemoved label '{label_name}' from PR #{pr_number}")
        return True
    except Exception as e:
        print(f"\tFailed to remove label '{label_name}' from PR #{pr_number}: {e}")
        print("Failed to get valid response after retries. Exiting script.")
        sys.exit(1)
