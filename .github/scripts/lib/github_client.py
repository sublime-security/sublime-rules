"""
GitHub API session setup with retry logic.
"""
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


def create_github_session(token):
    """
    Create a requests session configured for GitHub API with retry logic.

    Args:
        token (str): GitHub token. Required.

    Returns:
        requests.Session: Configured session with retry strategy and auth headers.

    Raises:
        ValueError: If token is not provided.
    """
    if not token:
        raise ValueError("GitHub token is required")

    # Configure retry strategy
    retry_strategy = Retry(
        total=3,  # Maximum number of retries
        backoff_factor=2,  # Exponential backoff factor (wait 2^retry seconds)
        status_forcelist=[429, 500, 502, 503, 504],  # HTTP status codes to retry on
        allowed_methods=["HEAD", "GET", "POST", "PUT", "DELETE", "OPTIONS", "TRACE"]
    )

    adapter = HTTPAdapter(max_retries=retry_strategy)
    session = requests.Session()
    session.mount("http://", adapter)
    session.mount("https://", adapter)

    headers = {
        'Authorization': f'token {token}',
        'Accept': 'application/vnd.github.v3+json'
    }
    session.headers.update(headers)

    return session
