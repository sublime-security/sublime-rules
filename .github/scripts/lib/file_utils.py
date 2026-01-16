"""
File operations and GitHub file content utilities.
"""
import base64
import os


def get_file_contents(session, repo_owner, repo_name, file_path, ref):
    """
    Get file contents from GitHub at a specific commit.

    Args:
        session: GitHub API session
        repo_owner (str): Repository owner
        repo_name (str): Repository name
        file_path (str): Path to the file in the repository
        ref (str): Git ref (branch, tag, or commit SHA) to fetch from

    Returns:
        str: Decoded file content
    """
    # Construct the contents API URL with the specific ref
    url = f'https://api.github.com/repos/{repo_owner}/{repo_name}/contents/{file_path}'
    params = {'ref': ref}

    response = session.get(url, params=params)
    response.raise_for_status()
    content = response.json()['content']
    return base64.b64decode(content).decode('utf-8')


def save_file(output_folder, path, content):
    """
    Save content to a file in the output folder.

    Args:
        output_folder (str): Base output folder path
        path (str): Filename or path to save
        content (str): Content to write
    """
    file_path = os.path.join(output_folder, os.path.basename(path))
    with open(file_path, 'w') as file:
        file.write(content)


def pr_has_synced_files(output_folder, pr_number):
    """
    Check if a PR has any synced files in the output folder.

    Args:
        output_folder (str): Base output folder path
        pr_number (int): Pull request number

    Returns:
        bool: True if files exist for this PR, False otherwise
    """
    if not os.path.exists(output_folder):
        return False
    prefix = f"{pr_number}_"
    for filename in os.listdir(output_folder):
        if filename.startswith(prefix) and filename.endswith('.yml'):
            return True
    return False


def clean_output_folder(output_folder, valid_files):
    """
    Remove files from output folder that are not in the valid_files set.

    Args:
        output_folder (str): Base output folder path
        valid_files (set): Set of filenames to keep
    """
    if not os.path.exists(output_folder):
        return
    for filename in os.listdir(output_folder):
        file_path = os.path.join(output_folder, filename)
        if filename not in valid_files:
            print(f"Removing file: {filename}")
            os.remove(file_path)


def is_detection_rule_file(file):
    """
    Check if a file is a detection rule YAML file.

    Args:
        file (dict): File object from GitHub API with 'filename' and 'status' keys

    Returns:
        bool: True if file is a detection rule YAML in an eligible status
    """
    return (
        file['status'] in ['added', 'modified', 'changed'] and
        file['filename'].startswith('detection-rules/') and
        file['filename'].endswith('.yml')
    )


def should_process_file(file, include_added=True, include_updates=True):
    """
    Check if a PR file should be processed as a detection rule.

    Args:
        file (dict): File object from GitHub API
        include_added (bool): Whether to include newly added files
        include_updates (bool): Whether to include modified/changed files

    Returns:
        bool: True if file should be processed
    """
    if not is_detection_rule_file(file):
        return False
    if file['status'] == 'added':
        return include_added
    if file['status'] in ['modified', 'changed']:
        return include_updates
    return False


def count_yaml_rules_in_pr(files):
    """
    Count the number of YAML rule files in the PR.

    Args:
        files (list): List of file objects from GitHub API

    Returns:
        int: Number of YAML files in detection-rules directory
    """
    return sum(1 for file in files if is_detection_rule_file(file))
