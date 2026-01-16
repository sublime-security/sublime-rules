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


def count_yaml_rules_in_pr(files):
    """
    Count the number of YAML rule files in the PR.

    Args:
        files (list): List of file objects from GitHub API

    Returns:
        int: Number of YAML files in detection-rules directory
    """
    yaml_count = 0
    for file in files:
        if (file['status'] in ['added', 'modified', 'changed'] and
            file['filename'].startswith('detection-rules/') and
                file['filename'].endswith('.yml')):
            yaml_count += 1
    return yaml_count
