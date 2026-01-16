"""
Caching utilities to reduce redundant API calls.

This module provides a caching layer for PR-related GitHub API data to avoid
making redundant API calls for the same information multiple times during
a single script run.
"""
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

# Default number of parallel workers for API calls
# Keep conservative to avoid rate limiting
DEFAULT_WORKERS = 10


class PRCache:
    """Cache for PR-related data to avoid redundant API calls."""

    def __init__(self):
        self._labels = {}         # {pr_number: set(labels)}
        self._comments = {}       # {pr_number: [comments]}
        self._membership = {}     # {username: bool}
        self._pr_files = {}       # {pr_number: [files]}
        self._file_contents = {}  # {(repo_owner, repo_name, path, ref): content}

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

    def get_pr_files(self, session, repo_owner, repo_name, pr_number):
        """
        Get files for a PR, fetching from API only once.

        Args:
            session: GitHub API session
            repo_owner (str): Repository owner
            repo_name (str): Repository name
            pr_number (int): Pull request number

        Returns:
            list: List of file dictionaries
        """
        if pr_number not in self._pr_files:
            url = f'https://api.github.com/repos/{repo_owner}/{repo_name}/pulls/{pr_number}/files'
            response = session.get(url)
            response.raise_for_status()
            self._pr_files[pr_number] = response.json()
        return self._pr_files[pr_number]

    def get_file_content(self, session, repo_owner, repo_name, path, ref):
        """
        Get file content, fetching from API only once.

        Args:
            session: GitHub API session
            repo_owner (str): Repository owner
            repo_name (str): Repository name
            path (str): File path
            ref (str): Git reference (commit SHA)

        Returns:
            str: File content
        """
        cache_key = (repo_owner, repo_name, path, ref)
        if cache_key not in self._file_contents:
            url = f'https://api.github.com/repos/{repo_owner}/{repo_name}/contents/{path}?ref={ref}'
            response = session.get(url)
            response.raise_for_status()
            import base64
            self._file_contents[cache_key] = base64.b64decode(response.json()['content']).decode('utf-8')
        return self._file_contents[cache_key]

    def prefetch_labels(self, session, repo_owner, repo_name, pr_numbers, max_workers=DEFAULT_WORKERS):
        """
        Prefetch labels for multiple PRs in parallel.

        Args:
            session: GitHub API session
            repo_owner (str): Repository owner
            repo_name (str): Repository name
            pr_numbers (list): List of PR numbers to prefetch
            max_workers (int): Maximum parallel workers
        """
        # Filter out PRs we already have cached
        to_fetch = [pr for pr in pr_numbers if pr not in self._labels]
        if not to_fetch:
            return

        print(f"\tPrefetching labels for {len(to_fetch)} PRs...")

        def fetch_labels(pr_number):
            url = f'https://api.github.com/repos/{repo_owner}/{repo_name}/issues/{pr_number}/labels'
            response = session.get(url)
            response.raise_for_status()
            return pr_number, {label['name'] for label in response.json()}

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(fetch_labels, pr): pr for pr in to_fetch}
            for future in as_completed(futures):
                try:
                    pr_number, labels = future.result()
                    self._labels[pr_number] = labels
                except Exception as e:
                    pr = futures[future]
                    print(f"\tError prefetching labels for PR #{pr}: {e}")

    def prefetch_pr_files(self, session, repo_owner, repo_name, pr_numbers, max_workers=DEFAULT_WORKERS):
        """
        Prefetch file lists for multiple PRs in parallel.

        Args:
            session: GitHub API session
            repo_owner (str): Repository owner
            repo_name (str): Repository name
            pr_numbers (list): List of PR numbers to prefetch
            max_workers (int): Maximum parallel workers
        """
        # Filter out PRs we already have cached
        to_fetch = [pr for pr in pr_numbers if pr not in self._pr_files]
        if not to_fetch:
            return

        print(f"\tPrefetching files for {len(to_fetch)} PRs...")

        def fetch_files(pr_number):
            url = f'https://api.github.com/repos/{repo_owner}/{repo_name}/pulls/{pr_number}/files'
            response = session.get(url)
            response.raise_for_status()
            return pr_number, response.json()

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(fetch_files, pr): pr for pr in to_fetch}
            for future in as_completed(futures):
                try:
                    pr_number, files = future.result()
                    self._pr_files[pr_number] = files
                except Exception as e:
                    pr = futures[future]
                    print(f"\tError prefetching files for PR #{pr}: {e}")

    def prefetch_file_contents(self, session, repo_owner, repo_name, file_specs, max_workers=DEFAULT_WORKERS):
        """
        Prefetch file contents in parallel.

        Args:
            session: GitHub API session
            repo_owner (str): Repository owner
            repo_name (str): Repository name
            file_specs (list): List of (path, ref) tuples
            max_workers (int): Maximum parallel workers
        """
        import base64

        # Filter out files we already have cached
        to_fetch = [(path, ref) for path, ref in file_specs
                    if (repo_owner, repo_name, path, ref) not in self._file_contents]
        if not to_fetch:
            return

        print(f"\tPrefetching {len(to_fetch)} file contents...")

        def fetch_content(path, ref):
            url = f'https://api.github.com/repos/{repo_owner}/{repo_name}/contents/{path}?ref={ref}'
            response = session.get(url)
            response.raise_for_status()
            content = base64.b64decode(response.json()['content']).decode('utf-8')
            return path, ref, content

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(fetch_content, path, ref): (path, ref) for path, ref in to_fetch}
            for future in as_completed(futures):
                try:
                    path, ref, content = future.result()
                    cache_key = (repo_owner, repo_name, path, ref)
                    self._file_contents[cache_key] = content
                except Exception as e:
                    path, ref = futures[future]
                    print(f"\tError prefetching content for {path}@{ref[:7]}: {e}")
