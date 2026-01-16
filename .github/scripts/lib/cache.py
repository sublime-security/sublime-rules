"""
Caching utilities to reduce redundant API calls.

This module provides a caching layer for PR-related GitHub API data to avoid
making redundant API calls for the same information multiple times during
a single script run.
"""
import sys


class PRCache:
    """Cache for PR-related data to avoid redundant API calls."""

    def __init__(self):
        self._labels = {}      # {pr_number: set(labels)}
        self._comments = {}    # {pr_number: [comments]}
        self._membership = {}  # {username: bool}

    def get_labels(self, session, repo_owner, repo_name, pr_number):
        """
        Get labels for a PR, fetching from API only once.

        Args:
            session: GitHub API session
            repo_owner (str): Repository owner
            repo_name (str): Repository name
            pr_number (int): Pull request number

        Returns:
            set: Set of label names
        """
        if pr_number not in self._labels:
            url = f'https://api.github.com/repos/{repo_owner}/{repo_name}/issues/{pr_number}/labels'
            response = session.get(url)
            response.raise_for_status()
            self._labels[pr_number] = {label['name'] for label in response.json()}
        return self._labels[pr_number]

    def has_label(self, session, repo_owner, repo_name, pr_number, label_name):
        """
        Check if PR has label using cache.

        Args:
            session: GitHub API session
            repo_owner (str): Repository owner
            repo_name (str): Repository name
            pr_number (int): Pull request number
            label_name (str): Label name to check for

        Returns:
            bool: True if PR has the label, False otherwise
        """
        labels = self.get_labels(session, repo_owner, repo_name, pr_number)
        return label_name in labels

    def invalidate_labels(self, pr_number):
        """
        Invalidate label cache after applying/removing labels.

        Args:
            pr_number (int): Pull request number
        """
        self._labels.pop(pr_number, None)

    def get_comments(self, session, repo_owner, repo_name, pr_number):
        """
        Get comments for a PR, fetching from API only once.

        Args:
            session: GitHub API session
            repo_owner (str): Repository owner
            repo_name (str): Repository name
            pr_number (int): Pull request number

        Returns:
            list: List of comment dictionaries
        """
        if pr_number not in self._comments:
            url = f'https://api.github.com/repos/{repo_owner}/{repo_name}/issues/{pr_number}/comments'
            response = session.get(url)
            response.raise_for_status()
            self._comments[pr_number] = response.json()
        return self._comments[pr_number]

    def is_user_in_org(self, session, username, org_name):
        """
        Check org membership using cache.

        Args:
            session: GitHub API session
            username (str): GitHub username
            org_name (str): Organization name

        Returns:
            bool: True if user is a member, False otherwise
        """
        cache_key = f"{username}:{org_name}"
        if cache_key not in self._membership:
            url = f'https://api.github.com/orgs/{org_name}/members/{username}'
            try:
                response = session.get(url)
                # 404 is expected when user is not in org
                if response.status_code == 404:
                    self._membership[cache_key] = False
                else:
                    response.raise_for_status()
                    self._membership[cache_key] = (response.status_code == 204)
            except Exception as e:
                print(f"Error checking organization membership for {username} in {org_name}: {e}")
                print("Failed to get valid response after retries. Exiting script.")
                sys.exit(1)
        return self._membership[cache_key]
