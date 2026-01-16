"""GitHub API operations for PR management."""


def get_pull_requests(session, repo_owner, repo_name, state='open', max_results=None):
    """
    Fetch pull requests from the repository.

    Args:
        session: GitHub API session
        repo_owner: Repository owner
        repo_name: Repository name
        state: PR state - 'open', 'closed', or 'all' (default 'open')
        max_results: Maximum number of PRs to fetch, None for all (default None)

    Returns:
        list: List of pull request objects
    """
    pull_requests = []
    page = 1
    per_page = 30
    state_label = state.upper() if state != 'open' else ''

    while True:
        if max_results and len(pull_requests) >= max_results:
            print(f"hit max {state} prs length")
            break

        url = f'https://api.github.com/repos/{repo_owner}/{repo_name}/pulls'
        params = {
            'page': page,
            'per_page': per_page,
            'state': state,
            'sort': 'updated',
            'direction': 'desc'
        }
        print(f"Fetching page {page} of {state_label} Pull Requests".strip())
        response = session.get(url, params=params)
        response.raise_for_status()

        pull_requests.extend(response.json())

        if 'Link' in response.headers:
            links = response.headers['Link'].split(', ')
            has_next = any('rel="next"' in link for link in links)
        else:
            has_next = False

        if not has_next:
            print(f"Fetched page {page} of {state_label} Pull Requests".strip())
            print(f"PRs on page {page}: {len(response.json())}")
            break

        print(f"Fetched page {page} of {state_label} Pull Requests".strip())
        print(f"{state_label} PRs on page {page}: {len(response.json())}".strip())
        print(f"{state_label} PRs found so far: {len(pull_requests)}".strip())
        print(f"Moving to page {page + 1}")
        page += 1

    print(f"Total {state_label} PRs: {len(pull_requests)}".strip())
    return pull_requests


def get_files_for_pull_request(session, repo_owner, repo_name, pr_number):
    """
    Fetch files changed in a pull request.

    Args:
        session: GitHub API session
        repo_owner: Repository owner
        repo_name: Repository name
        pr_number: Pull request number

    Returns:
        list: List of file objects with status and filename
    """
    url = f'https://api.github.com/repos/{repo_owner}/{repo_name}/pulls/{pr_number}/files'
    response = session.get(url)
    response.raise_for_status()
    return response.json()
