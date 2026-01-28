"""
GraphQL client for bulk PR data fetching.

This module provides efficient bulk fetching of PR data via GitHub's GraphQL API,
reducing API calls from 500-600+ to 1-2 per script run.
"""
from typing import List, Optional

GITHUB_GRAPHQL_URL = "https://api.github.com/graphql"

# GraphQL query to fetch PRs with all related data in a single request
PR_QUERY = """
query GetPullRequests($owner: String!, $repo: String!, $states: [PullRequestState!], $cursor: String) {
  repository(owner: $owner, name: $repo) {
    pullRequests(first: 100, states: $states, after: $cursor, orderBy: {field: UPDATED_AT, direction: DESC}) {
      pageInfo {
        hasNextPage
        endCursor
      }
      nodes {
        number
        title
        isDraft
        state
        mergedAt
        closedAt
        url
        baseRefName
        headRefOid
        authorAssociation
        author {
          login
        }
        labels(first: 20) {
          nodes {
            name
          }
        }
        files(first: 100) {
          nodes {
            path
            changeType
          }
        }
        comments(first: 50) {
          nodes {
            body
            authorAssociation
            author {
              login
            }
          }
        }
        commits(last: 1) {
          nodes {
            commit {
              statusCheckRollup {
                contexts(first: 50) {
                  nodes {
                    ... on CheckRun {
                      name
                      conclusion
                      status
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  }
}
"""

# Mapping from GraphQL changeType to REST API status format
_CHANGE_TYPE_MAP = {
    'ADDED': 'added',
    'MODIFIED': 'modified',
    'CHANGED': 'changed',
    'DELETED': 'deleted',
    'RENAMED': 'renamed',
    'COPIED': 'copied',
}


def create_graphql_session(token: str):
    """
    Create a requests session configured for GitHub GraphQL API.

    Args:
        token: GitHub token with appropriate permissions.

    Returns:
        requests.Session: Configured session with auth headers for GraphQL.

    Raises:
        ValueError: If token is not provided.
    """
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry

    if not token:
        raise ValueError("GitHub token is required")

    retry_strategy = Retry(
        total=3,
        backoff_factor=2,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["POST"]
    )

    adapter = HTTPAdapter(max_retries=retry_strategy)
    session = requests.Session()
    session.mount("https://", adapter)

    headers = {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json',
    }
    session.headers.update(headers)

    return session


def _execute_graphql(session, query: str, variables: dict) -> dict:
    """
    Execute a GraphQL query.

    Args:
        session: GraphQL-configured requests session.
        query: GraphQL query string.
        variables: Query variables.

    Returns:
        dict: Response data.

    Raises:
        Exception: If the GraphQL query fails.
    """
    response = session.post(
        GITHUB_GRAPHQL_URL,
        json={'query': query, 'variables': variables}
    )
    response.raise_for_status()

    result = response.json()
    if 'errors' in result:
        raise Exception(f"GraphQL errors: {result['errors']}")

    return result['data']


def _parse_pr_node(node: dict) -> dict:
    """
    Parse a GraphQL PR node into a standardized dictionary.

    Args:
        node: Raw PR node from GraphQL response.

    Returns:
        dict: Parsed PR data.
    """
    from .pr_data import PRData

    # Extract labels
    labels = {label['name'] for label in node.get('labels', {}).get('nodes', [])}

    # Extract files with status mapping
    files = [
        {
            'filename': f['path'],
            'status': _CHANGE_TYPE_MAP.get(f['changeType'], f['changeType'].lower())
        }
        for f in node.get('files', {}).get('nodes', [])
    ]

    # Extract comments
    comments = [
        {
            'body': c['body'],
            'author_login': c['author']['login'] if c.get('author') else None,
            'author_association': c['authorAssociation'],
        }
        for c in node.get('comments', {}).get('nodes', [])
    ]

    # Extract check runs from the last commit
    check_runs = []
    commits = node.get('commits', {}).get('nodes', [])
    if commits:
        last_commit = commits[0]
        status_rollup = last_commit.get('commit', {}).get('statusCheckRollup')
        if status_rollup:
            contexts = status_rollup.get('contexts', {}).get('nodes', [])
            for ctx in contexts:
                # Only include check runs (not status contexts)
                if 'name' in ctx:
                    check_runs.append({
                        'name': ctx.get('name', ''),
                        'conclusion': ctx.get('conclusion'),
                        'status': ctx.get('status'),
                    })

    return PRData(
        number=node['number'],
        title=node['title'],
        is_draft=node['isDraft'],
        state=node['state'],
        merged_at=node.get('mergedAt'),
        closed_at=node.get('closedAt'),
        url=node['url'],
        base_ref=node['baseRefName'],
        head_sha=node['headRefOid'],
        author_login=node['author']['login'] if node.get('author') else None,
        author_association=node['authorAssociation'],
        labels=labels,
        files=files,
        comments=comments,
        check_runs=check_runs,
    )


def fetch_all_prs(session, owner: str, repo: str, states: Optional[List[str]] = None, max_results: Optional[int] = None):
    """
    Fetch all PRs with labels, files, comments, and check runs in 1-2 API calls.

    Args:
        session: GraphQL-configured requests session.
        owner: Repository owner.
        repo: Repository name.
        states: List of PR states to fetch ('OPEN', 'CLOSED', 'MERGED').
                Defaults to ['OPEN'].
        max_results: Maximum number of PRs to fetch. None for unlimited.

    Returns:
        List[PRData]: List of PRData objects.
    """
    if states is None:
        states = ['OPEN']

    all_prs = []
    cursor = None
    page = 1

    while True:
        print(f"Fetching page {page} of Pull Requests via GraphQL...")

        variables = {
            'owner': owner,
            'repo': repo,
            'states': states,
            'cursor': cursor,
        }

        data = _execute_graphql(session, PR_QUERY, variables)
        pull_requests = data['repository']['pullRequests']

        nodes = pull_requests['nodes']
        for node in nodes:
            pr_data = _parse_pr_node(node)
            all_prs.append(pr_data)

            if max_results and len(all_prs) >= max_results:
                print(f"Reached max results ({max_results}), stopping fetch")
                return all_prs

        page_info = pull_requests['pageInfo']
        print(f"Fetched {len(nodes)} PRs on page {page}, total so far: {len(all_prs)}")

        if not page_info['hasNextPage']:
            break

        cursor = page_info['endCursor']
        page += 1

    print(f"Total PRs fetched: {len(all_prs)}")
    return all_prs
