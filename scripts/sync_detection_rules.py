import base64
import os
import sys
import uuid
from datetime import datetime, timedelta, timezone
import re
from urllib.parse import quote

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Common configuration
GITHUB_TOKEN = os.getenv('GITHUB_TOKEN')
SUBLIME_API_TOKEN = os.getenv('SUBLIME_API_TOKEN')
REPO_OWNER = os.getenv('REPO_OWNER', 'sublime-security')
REPO_NAME = os.getenv('REPO_NAME', 'sublime-rules')
OUTPUT_FOLDER = os.getenv('OUTPUT_FOLDER', 'detection-rules')

# Script mode selection (default to 'standard' if not specified)
# Possible values: 'standard', 'test-rules'
SCRIPT_MODE = os.getenv('SCRIPT_MODE', 'standard')

# flag to control adding the author name into the tag
ADD_AUTHOR_TAG = os.getenv('ADD_AUTHOR_TAG', 'true').lower() == 'true'
AUTHOR_TAG_PREFIX = os.getenv('AUTHOR_TAG_PREFIX', 'pr_author_')

# flag to control of an additional tag is created which
# indicates the file status (modified vs added)
ADD_RULE_STATUS_TAG = os.getenv('ADD_RULE_STATUS_TAG', 'true').lower() == 'true'
RULE_STATUS_PREFIX = os.getenv('RULE_STATUS_PREFIX', 'rule_status_')

# flag to control if a reference is added which links to the PR in the repo
ADD_PR_REFERENCE = os.getenv('ADD_PR_REFERENCE', 'true').lower() == 'true'

# flag to enable creating a rule in the feed for net new rules
INCLUDE_ADDED = os.getenv('INCLUDE_ADDED', 'true').lower() == 'true'
# flag to enable creating a rule in the feed for updated (not net new) rules
INCLUDE_UPDATES = os.getenv('INCLUDE_UPDATES', 'true').lower() == 'true'
# flag to enable the removing rules from the platform when the PR is closed
DELETE_RULES_FROM_CLOSED_PRS = os.getenv('DELETE_RULES_FROM_CLOSED_PRS', 'true').lower() == 'true'
# variable that controls when the rules from a closed PR should be deleted
# this is in days
DELETE_RULES_FROM_CLOSED_PRS_DELAY = int(os.getenv('DELETE_RULES_FROM_CLOSED_PRS_DELAY', '3'))

# flag to add "created_from_open_prs" tag
CREATE_OPEN_PR_TAG = os.getenv('CREATE_OPEN_PR_TAG', 'true').lower() == 'true'
OPEN_PR_TAG = os.getenv('OPEN_PR_TAG', 'created_from_open_prs')

# # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Start test-rules mode configuration options         #
# The below options only apply when mode = test-rules #
# # # # # # # # # # # # # # # # # # # # # # # # # # # #

# flag to enable filtering PRs by organization membership
FILTER_BY_ORG_MEMBERSHIP = os.getenv('FILTER_BY_ORG_MEMBERSHIP', 'false').lower() == 'true'
# organization name to filter by
ORG_NAME = os.getenv('ORG_NAME', 'sublime-security')

# flag to enable including PRs with specific comments
INCLUDE_PRS_WITH_COMMENT = os.getenv('INCLUDE_PRS_WITH_COMMENT', 'false').lower() == 'true'
# comment text that triggers inclusion
COMMENT_TRIGGER = os.getenv('COMMENT_TRIGGER', '/update-test-rules')

# flag to enable applying labels to PRs
ADD_TEST_RULES_LABEL = os.getenv('ADD_TEST_RULES_LABEL', 'false').lower() == 'true'
# label to apply to PRs that have rules in test-rules
IN_TEST_RULES_LABEL = os.getenv('IN_TEST_RULES_LABEL', 'in-test-rules')
# label to apply to PRs that are excluded due to author membership
AUTHOR_MEMBERSHIP_EXCLUSION_LABEL = os.getenv('AUTHOR_MEMBERSHIP_EXCLUSION_LABEL', 'test-rules:excluded:author_membership')

# flag to skip files containing specific text patterns
# this is due to test-rules not supporting specific functions
SKIP_FILES_WITH_TEXT = os.getenv('SKIP_FILES_WITH_TEXT', 'false').lower() == 'true'
# Skip texts configuration: {text: [labels_to_apply]}
SKIP_TEXTS = {
    'ml.link_analysis': ['hunting-required', 'test-rules:excluded:link_analysis']
}

# # flag to enable skipping PRs with too many rules
SKIP_BULK_PRS = os.getenv('SKIP_BULK_PRS', 'false').lower() == 'true'
# maximum number of YAML rules allowed in a PR before skipping
MAX_RULES_PER_PR = int(os.getenv('MAX_RULES_PER_PR', '10'))
# label to apply to PRs that are skipped due to too many rules
BULK_PR_LABEL = os.getenv('BULK_PR_LABEL', 'test-rules:excluded:bulk_rules')

# flag to check if required actions have completed
# we should only include rules which have passed validation
CHECK_ACTION_COMPLETION = os.getenv('CHECK_ACTION_COMPLETION', 'true').lower() == 'true'
# name of the required workflow
REQUIRED_CHECK_NAME = os.getenv('REQUIRED_CHECK_NAME', 'Rule Tests and ID Updated')
# required conclusion of the workflow
REQUIRED_CHECK_CONCLUSION = os.getenv('REQUIRED_CHECK_CONCLUSION', 'success')

# # # # # # # # # # # # # # # # # # # # # # #
# end test-rules mode configuration options #
# # # # # # # # # # # # # # # # # # # # # # #

# Create output folder if it doesn't exist
if not os.path.exists(OUTPUT_FOLDER):
    os.makedirs(OUTPUT_FOLDER)

# Configure requests session with retry strategy for GitHub API
retry_strategy = Retry(
    total=3,  # Maximum number of retries
    backoff_factor=2,  # Exponential backoff factor (wait 2^retry seconds)
    status_forcelist=[429, 500, 502, 503, 504],  # HTTP status codes to retry on
    allowed_methods=["HEAD", "GET", "POST", "PUT", "DELETE", "OPTIONS", "TRACE"]
)

adapter = HTTPAdapter(max_retries=retry_strategy)
github_session = requests.Session()
github_session.mount("http://", adapter)
github_session.mount("https://", adapter)

headers = {
    'Authorization': f'token {GITHUB_TOKEN}',
    'Accept': 'application/vnd.github.v3+json'
}

# Configure session headers
github_session.headers.update(headers)

def has_label(pr_number, label_name):
    """
    Check if a PR has a specific label.

    Args:
        pr_number (int): Pull request number
        label_name (str): Label name to check for

    Returns:
        bool: True if PR has the label, False otherwise
    """
    url = f'https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/issues/{pr_number}/labels'
    response = github_session.get(url)
    response.raise_for_status()
    labels = response.json()
    
    return any(label['name'] == label_name for label in labels)

def apply_label(pr_number, label_name):
    """
    Apply a label to a PR.

    Args:
        pr_number (int): Pull request number
        label_name (str): Label name to apply

    Returns:
        bool: True if label was applied successfully, False otherwise
    """
    url = f'https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/issues/{pr_number}/labels'
    payload = {'labels': [label_name]}
    
    try:
        response = github_session.post(url, json=payload)
        response.raise_for_status()
        print(f"\tApplied label '{label_name}' to PR #{pr_number}")
        return True
    except Exception as e:
        print(f"\tFailed to apply label '{label_name}' to PR #{pr_number}: {e}")
        print("Failed to get valid response after retries. Exiting script.")
        sys.exit(1)

def remove_label(pr_number, label_name):
    """
    Remove a label from a PR.

    Args:
        pr_number (int): Pull request number
        label_name (str): Label name to remove

    Returns:
        bool: True if label was removed successfully, False otherwise
    """
    url = f'https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/issues/{pr_number}/labels/{label_name}'
    
    try:
        response = github_session.delete(url)
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

def is_user_in_org(username, org_name):
    """
    Check if a user is a member of a specific organization.

    Args:
        username (str): GitHub username
        org_name (str): Organization name

    Returns:
        bool: True if user is a member, False otherwise
    """
    url = f'https://api.github.com/orgs/{org_name}/members/{username}'
    try:
        response = github_session.get(url)
        # 404 is expected when user is not in org, so handle it separately
        if response.status_code == 404:
            return False
        response.raise_for_status()
        return response.status_code == 204
    except Exception as e:
        print(f"Error checking organization membership for {username} in {org_name}: {e}")
        print("Failed to get valid response after retries. Exiting script.")
        sys.exit(1)


def has_trigger_comment(pr_number, org_name, trigger_comment):
    """
    Check if a PR has a comment with the trigger text from a member of the specified org.

    Args:
        pr_number (int): Pull request number
        org_name (str): Organization name to filter commenters
        trigger_comment (str): Comment text to look for

    Returns:
        bool: True if a matching comment is found, False otherwise
    """
    url = f'https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/issues/{pr_number}/comments'
    response = github_session.get(url)
    response.raise_for_status()
    comments = response.json()

    for comment in comments:
        # Check if comment contains the trigger and author is in the organization
        if trigger_comment in comment['body']:
            print(f"\tPR #{pr_number}: Author not in {ORG_NAME} and trigger comment found")
            if is_user_in_org(comment['user']['login'], org_name):
                print(f"\tPR #{pr_number}: Author not in {ORG_NAME} and trigger comment from {comment['user']['login']} is a {ORG_NAME} member")
                return True
            print(f"\tPR #{pr_number}: Author not in {ORG_NAME} and trigger comment from {comment['user']['login']} is NOT a {ORG_NAME} member")

    print(f"\tPR #{pr_number}: Author not in {ORG_NAME} and trigger comment NOT found")

    return False


def has_required_action_completed(pr_sha, action_name, required_status):
    """
    Check if a required GitHub Actions workflow has completed with the expected status for a PR.
    Uses the GitHub Checks API to poll for check results.

    Args:
        pr_sha (str): SHA of the PR head commit
        action_name (str): Name of the action/check to look for
        required_status (str): Required status (success, failure, etc.)

    Returns:
        bool: True if the action has completed with the required status, False otherwise
    """
    # Use the GitHub Checks API to get all check runs for this commit
    url = f'https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/commits/{pr_sha}/check-runs'
    custom_headers = headers.copy()
    # Add the required Accept header for the Checks API
    custom_headers['Accept'] = 'application/vnd.github.v3+json'

    # Temporarily update session headers for this request
    original_accept = github_session.headers.get('Accept')
    github_session.headers.update(custom_headers)
    
    try:
        response = github_session.get(url)
        response.raise_for_status()
    except Exception as e:
        print(f"\tError checking action status: {e}")
        print("Failed to get valid response after retries. Exiting script.")
        sys.exit(1)
    finally:
        # Restore original Accept header
        github_session.headers['Accept'] = original_accept

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

def check_skip_texts(content, skip_texts):
    """
    Check if file content contains any of the configured skip texts (case-insensitive).

    Args:
        content (str): File content
        skip_texts (dict): Dictionary of {text: [labels]} to check

    Returns:
        tuple: (matched_texts, all_labels) where matched_texts is a list of 
               matching texts and all_labels is a set of all labels to apply
    """
    matched_texts = []
    all_labels = set()
    
    for text, labels in skip_texts.items():
        if text.lower() in content.lower():
            matched_texts.append(text)
            all_labels.update(labels)
    
    return matched_texts, all_labels


def generate_deterministic_uuid(seed_string):
    """
    Generate a deterministic UUID based on a seed string.
    This ensures the same input will always produce the same UUID.

    Args:
        seed_string (str): A string to use as a seed for UUID generation

    Returns:
        str: A UUID string in the format of XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX
    """
    # Create a namespace UUID (using the DNS namespace as a standard practice)
    namespace = uuid.UUID('6ba7b810-9dad-11d1-80b4-00c04fd430c8')

    # Create a UUID using the namespace and the seed string
    deterministic_uuid = uuid.uuid5(namespace, seed_string)

    return str(deterministic_uuid)


def add_id_to_yaml(content, filename):
    """
    Adds or replaces an ID field in the YAML content.
    Extracts the original ID if present.

    Args:
        content (str): The YAML content
        filename (str): The filename to use as seed for UUID generation

    Returns:
        tuple: (modified_content, original_id) - The modified YAML content with the UUID added/replaced
               and the original ID if found, otherwise None
    """
    # Use the filename directly as the seed for UUID generation
    # Generate a deterministic UUID based on the seed
    new_uuid = generate_deterministic_uuid(filename)
    original_id = None

    # Check if 'id:' already exists in the content
    if 'id:' in content:
        # Extract the original ID
        pattern = r'^\s*id:\s*([^\n]*)'
        match = re.search(pattern, content, flags=re.MULTILINE)
        if match:
            original_id = match.group(1).strip()
            if original_id.startswith('"') and original_id.endswith('"'):
                original_id = original_id[1:-1]  # Remove surrounding quotes
            elif original_id.startswith("'") and original_id.endswith("'"):
                original_id = original_id[1:-1]  # Remove surrounding quotes

        # Replace with the new ID
        modified_content = re.sub(pattern, f'id: \"{new_uuid}\"', content, flags=re.MULTILINE)
        return modified_content, original_id
    else:
        # If it doesn't exist, add it to the very end of the YAML file
        # Make sure we have a clean end to the file (no trailing whitespace)
        modified_content = content.rstrip()

        # Add a newline and the ID field
        modified_content += f"\nid: \"{new_uuid}\""

        return modified_content, original_id


def search_sublime_rule_feed(rule_name):
    # strip quotes for searching
    rule_name = rule_name.strip("\"\'")
    rule_name = quote(rule_name)
    # print(f"Searching Sublime for rules with name: {rule_name}")
    url = f"https://platform.sublime.security/v0/rules?limit=50&offset=0&search={rule_name}"

    headers = {
        "accept": "application/json",
        "authorization": f"Bearer {SUBLIME_API_TOKEN}"
    }
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
    except requests.exceptions.HTTPError as err:
        print(f"HTTP error occurred: {err}")
        # the calling function handles None
        return None
    except requests.exceptions.ConnectionError as err:
        print(f"Connection error occurred: {err}")
        # the calling function handles None
        return None
    else:
        print(f"\tSearch Feed Response Code: {response.status_code}")
        response = response.json()
        print(f"\tSearch Feed Found Count: {response['count']}")
        return response


def sublime_delete_rule(rule_id):
    url = f"https://platform.sublime.security/v0/rules/{rule_id}"

    headers = {
        "accept": "application/json",
        "authorization": f"Bearer {SUBLIME_API_TOKEN}"
    }
    response = requests.delete(url, headers=headers)

    print(f"\tDelete Rule Response Code: {response.status_code}")

    return response.ok


def get_closed_pull_requests():
    closed_pull_requests = []
    page = 1
    per_page = 30  # 100 is the max allowed items per page by GitHub API
    max_closed = 60

    while len(closed_pull_requests) <= max_closed:
        if len(closed_pull_requests) >= max_closed:
            print("hit max closed prs length")
            break

        url = f'https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/pulls'
        params = {'page': page, 'per_page': per_page, 'state': 'closed', 'sort': 'updated', 'direction': 'desc'}
        print(f"Fetching page {page} of CLOSED Pull Requests")
        response = github_session.get(url, params=params)
        response.raise_for_status()

        # Extend the list with the pull requests from the current page
        closed_pull_requests.extend(response.json())

        # Check if there is a 'Link' header and whether it contains 'rel="next"'
        if 'Link' in response.headers:
            links = response.headers['Link'].split(', ')
            has_next = any('rel="next"' in link for link in links)
        else:
            has_next = False

        if not has_next:
            print(f"Fetched page {page} of Pull Requests")
            print(f"PRs on page {page}: {len(response.json())}")
            break  # No more pages, exit loop

        print(f"Fetched page {page} of CLOSED Pull Requests")
        print(f"CLOSED PRs on page {page}: {len(response.json())}")
        print(f"CLOSED PRs found so far: {len(closed_pull_requests)}")
        print(f"Moving to page {page + 1}")
        page += 1  # Move to the next page

    print(f"Total CLOSED PRs: {len(closed_pull_requests)}")
    return closed_pull_requests


def get_open_pull_requests():
    pull_requests = []
    page = 1
    per_page = 30  # 100 is the max allowed items per page by GitHub API

    while True:
        url = f'https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/pulls'
        params = {'page': page, 'per_page': per_page, 'sort': 'updated', 'direction': 'desc'}
        print(f"Fetching page {page} of Pull Requests")
        response = github_session.get(url, params=params)
        response.raise_for_status()

        # Extend the list with the pull requests from the current page
        pull_requests.extend(response.json())

        # Check if there is a 'Link' header and whether it contains 'rel="next"'
        if 'Link' in response.headers:
            links = response.headers['Link'].split(', ')
            has_next = any('rel="next"' in link for link in links)
        else:
            has_next = False

        if not has_next:
            print(f"Fetched page {page} of Pull Requests")
            print(f"PRs on page {page}: {len(response.json())}")
            break  # No more pages, exit loop

        print(f"Fetched page {page} of Pull Requests")
        print(f"PRs on page {page}: {len(response.json())}")
        print(f"PRs found so far: {len(pull_requests)}")
        print(f"Moving to page {page + 1}")
        page += 1  # Move to the next page

    print(f"Total PRs: {len(pull_requests)}")
    return pull_requests


def get_files_for_pull_request(pr_number):
    url = f'https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/pulls/{pr_number}/files'
    response = github_session.get(url)
    response.raise_for_status()
    return response.json()


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


def get_file_contents(contents_url):
    response = github_session.get(contents_url)
    response.raise_for_status()
    content = response.json()['content']
    return base64.b64decode(content).decode('utf-8')


def save_file(path, content):
    file_path = os.path.join(OUTPUT_FOLDER, os.path.basename(path))
    with open(file_path, 'w') as file:
        file.write(content)


def clean_output_folder(valid_files):
    for filename in os.listdir(OUTPUT_FOLDER):
        file_path = os.path.join(OUTPUT_FOLDER, filename)
        if filename not in valid_files:
            print(f"Removing file: {filename}")
            os.remove(file_path)


def extract_rule_name(content):
    current_name = ""
    lines = content.split('\n')
    for line in lines:
        if 'name:' in line:
            # print(f"Found name line: {line}")
            # replace the quotes and spaces to create a clean filename
            current_name = line.replace('name: ', '').strip()
            break

    return current_name


def prepend_pr_details(rule_name, pr):
    # maintain the original quoting around the name
    if rule_name.startswith('"') and rule_name.endswith('"'):
        new_name = f"\"PR# {pr['number']} - {rule_name.strip("\" ")}\""
    elif rule_name.startswith('\'') and rule_name.endswith('\''):
        new_name = f"\'PR# {pr['number']} - {rule_name.strip("\' ")}\'"
    else:
        new_name = f"PR# {pr['number']} - {rule_name}"
    # replace it in the content
    # print(f"New Name: {new_name}")
    # print(f"Old Name: {rule_name}")

    return new_name


def rename_rules(content, pr):
    # extract the current name
    current_name = extract_rule_name(content)
    # build out the new name to inject the PR number
    new_name = prepend_pr_details(current_name, pr)

    content = content.replace(current_name, new_name)
    return content


def add_block(yaml_string, block_name, value):
    # throw an error if the block name isn't known
    if block_name not in ['tags', 'references', 'tags:', 'references:']:
        raise ValueError(f'Block Name: {block_name} is unsupported')
    # if it doesn't have the : needed, add it.

    if not block_name.endswith(':'):
        block_name = f"{block_name}:"

    if block_name in yaml_string:
        # find the tags block
        start_block = yaml_string.find(block_name)

        #  the end of the block by locating the next section or end of the string
        end_block = start_block

        while True:
            next_line_start = yaml_string.find("\n", end_block + 1)
            ## if there isn't a new line found, we've hit the end of the file
            ## or if the next line doesn't start with a space (which indicates it's still within the tag section)
            if next_line_start == -1 or not yaml_string[next_line_start + 1].isspace():
                if next_line_start != -1:
                    end_block = next_line_start
                else:
                    len(yaml_string)
                break
            end_block = next_line_start

        # get the original block
        block = yaml_string[start_block:end_block].strip()

        existing_block_entries = []
        # Split the tags into a list
        for line in block.splitlines():
            # within the tags_block is the tag section header, skip that one
            if line.strip() == block_name:
                continue
            line = line.strip()
            line = line.lstrip('-')
            # strip leading spaces after the - too
            line = line.strip()

            existing_block_entries.append(line)
        # add the author tag to the existing tags array
        existing_block_entries.append(f"{value}")

        new_block_string = block_name
        for entry in existing_block_entries:
            new_block_string += f"\n  - {entry}"
        # replace the old with the new
        modified_yaml_string = yaml_string.replace(block, new_block_string)
    else:
        # just add it at the end
        new_block_string = f"{block_name}\n  - {value}"
        # add additional tag to help filter down to the right rule id later
        modified_yaml_string = yaml_string.strip() + "\n" + new_block_string

    return modified_yaml_string


def handle_closed_prs():
    """
    Handle closed PRs by deleting rules from closed PRs after a delay period.
    Uses comprehensive search by PR number pattern to catch all rules including orphaned ones.

    Returns:
        set: Set of rule IDs that were deleted
    """
    if not DELETE_RULES_FROM_CLOSED_PRS:
        return set()

    closed_pr_header = [
        ' _____ _                    _   ______      _ _   ______                           _       ',
        '/  __ \\ |                  | |  | ___ \\    | | |  | ___ \\                         | |      ',
        '| /  \\/ | ___  ___  ___  __| |  | |_/ /   _| | |  | |_/ /___  __ _ _   _  ___  ___| |_ ___ ',
        '| |   | |/ _ \\/ __|/ _ \\/ _\' |  |  __/ | | | | |  |    // _ \\/ _\' | | | |/ _ \\/ __| __/ __|',
        '| \\__/\\ | (_) \\__ \\  __/ (_| |  | |  | |_| | | |  | |\\ \\  __/ (_| | |_| |  __/\\__ \\ |_\\__ \\',
        ' \\____/_|\\___/|___/\\___|\\__,_|  \\_|   \\__,_|_|_|  \\_| \\_\\___|\\__, |\\__,_|\\___||___/\\__|___/',
        '                                                                | |                        ',
        '                                                                |_|                        ',
    ]

    for line in closed_pr_header:
        print(line)

    deleted_ids = set()
    closed_pull_requests = get_closed_pull_requests()

    for closed_pr in closed_pull_requests:
        pr_number = closed_pr['number']
        print(f"Processing CLOSED PR #{pr_number}: {closed_pr['title']}")

        if closed_pr['base']['ref'] != "main":
            print(
                f"\tSkipping non-main branch PR #{closed_pr['number']}: {closed_pr['title']} -- dest branch: {closed_pr['base']['ref']}")
            continue

        # we only care about the delay if it's been merged
        if closed_pr['merged_at'] is not None:
            merged_at_time = datetime.strptime(closed_pr['merged_at'], "%Y-%m-%dT%H:%M:%SZ").replace(
                tzinfo=timezone.utc)

            # if the PR has been merged, then we add this delay to allow the PR author to still get alerts
            if not merged_at_time <= datetime.now(tz=timezone.utc) - timedelta(days=DELETE_RULES_FROM_CLOSED_PRS_DELAY):
                time_remaining = (merged_at_time + timedelta(days=3)) - datetime.now(tz=timezone.utc)

                remaining_days = time_remaining.days
                remaining_hours, remaining_remainder = divmod(time_remaining.seconds, 3600)
                remaining_minutes, remaining_seconds = divmod(remaining_remainder, 60)

                print(
                    f"\tDELAY NOT MET: Skipping PR #{closed_pr['number']}: {closed_pr['title']}\n\tRemaining Time = {remaining_days} days, {remaining_hours} hours, {remaining_minutes} minutes, {remaining_seconds} seconds")
                continue

        # Search for all rules with this PR number pattern
        # This catches all rules created from this PR, including orphaned ones
        pr_search_pattern = f"PR# {pr_number} - "
        print(f"\tSearching for all rules with pattern: '{pr_search_pattern}'")

        found_rules = search_sublime_rule_feed(pr_search_pattern)
        if found_rules is None:
            print(f"\tError searching for rules with pattern '{pr_search_pattern}' for PR#{pr_number}")
            continue

        print(f"\tFound {found_rules['count']} rules matching PR pattern")

        # Process all found rules
        for found_rule in found_rules.get('rules', []):
            rule_name = found_rule.get('name', '')
            rule_id = found_rule.get('id', '')

            # Verify this rule actually belongs to this PR (double-check the pattern match)
            if not rule_name.startswith(pr_search_pattern):
                print(f"\tSkipping rule '{rule_name}' - doesn't match expected pattern")
                continue

            print(f"\tEvaluating rule: {rule_name}")

            # Verify this rule has the expected tags to confirm it was created by our script
            rule_tags = found_rule.get('tags', [])

            # Check for the open PR tag
            if CREATE_OPEN_PR_TAG and OPEN_PR_TAG not in rule_tags:
                print(f"\t\tSkipping rule - missing required tag '{OPEN_PR_TAG}'")
                continue

            # Check for the author tag if enabled
            if ADD_AUTHOR_TAG:
                expected_author_tag = f"{AUTHOR_TAG_PREFIX}{closed_pr['user']['login']}"
                if expected_author_tag not in rule_tags:
                    print(f"\t\tSkipping rule - missing expected author tag '{expected_author_tag}'")
                    print(f"\t\tRule tags: {rule_tags}")
                    continue

            # All checks passed - delete this rule
            print(f"\t\tRule matches all criteria - deleting rule ID: {rule_id}")
            deleted = sublime_delete_rule(rule_id)
            if deleted:
                print(f"\t\tDELETED rule: {rule_id}")
                deleted_ids.add(rule_id)
            else:
                print(f"\t\tERROR DELETING rule: {rule_id}")

    print(f"Deleted {len(deleted_ids)} Rules from Closed PRs:")
    for deleted_id in deleted_ids:
        print(f"\t{deleted_id}")

    return deleted_ids

def handle_pr_rules(mode):
    """
    Process open PRs to create rules based on the specified mode.

    This function handles both standard mode and test-rules mode processing.
    In test-rules mode, it adds special fields required for test rules (og_id, testing_pr, testing_sha).

    Args:
        mode (str): Either 'standard' or 'test-rules'

    Returns:
        set: Set of filenames that were processed
    """
    # Display appropriate header based on mode
    if mode == 'standard':
        header = [
            ' _____                    ______      _ _   ______                           _       ',
            '|  _  |                   | ___ \\    | | |  | ___ \\                         | |      ',
            '| | | |_ __   ___ _ __    | |_/ /   _| | |  | |_/ /___  __ _ _   _  ___  ___| |_ ___ ',
            '| | | | \'_ \\ / _ \\ \'_ \\   |  __/ | | | | |  |    // _ \\/ _\' | | | |/ _ \\/ __| __/ __|',
            '\\ \\_/ / |_) |  __/ | | |  | |  | |_| | | |  | |\\ \\  __/ (_| | |_| |  __/\\__ \\ |_\\__ \\',
            ' \\___/| .__/ \\___|_| |_|  \\_|   \\__,_|_|_|  \\_| \\_\\___|\\__, |\\__,_|\\___||___/\\__|___/',
            '      | |                                                 | |                        ',
            '      |_|                                                 |_|                        ',
        ]
    else:  # test-rules mode
        header = [
            ' _____         _     ______      _          ',
            '|_   _|       | |    | ___ \\    | |         ',
            '  | | ___  ___| |_   | |_/ /   _| | ___  ___ ',
            '  | |/ _ \\/ __| __|  |    / | | | |/ _ \\/ __|',
            '  | |  __/\\__ \\ |_   | |\\ \\ |_| | |  __/\\__ \\',
            '  \\_/\\___||___/\\__|  \\_| \\_\\__,_|_|\\___||___/',
            '                                            ',
        ]

    for line in header:
        print(line)

    pull_requests = get_open_pull_requests()
    new_files = set()

    for pr in pull_requests:
        # Common checks for all modes
        if pr['draft']:
            print(f"Skipping draft PR #{pr['number']}: {pr['title']}")
            continue
        if pr['base']['ref'] != 'main':
            print(f"Skipping non-main branch PR #{pr['number']}: {pr['title']} -- dest branch: {pr['base']['ref']}")
            continue

        pr_number = pr['number']

        # Organization membership and comment trigger checks (for any mode if flags are set)
        process_pr = True
        print(f"Processing PR #{pr_number}: {pr['title']}")

        if FILTER_BY_ORG_MEMBERSHIP:
            author_in_org = is_user_in_org(pr['user']['login'], ORG_NAME)
            has_comment = False
            if author_in_org:
                print(f"\tPR #{pr['number']}: Author {pr['user']['login']} is in {ORG_NAME}")
            # only invoke has_trigger_comment when author_in_org is false
            if INCLUDE_PRS_WITH_COMMENT and not author_in_org:
                has_comment = has_trigger_comment(pr['number'], ORG_NAME, COMMENT_TRIGGER)
                
                # If trigger comment was found, remove the exclusion label
                if has_comment and has_label(pr_number, AUTHOR_MEMBERSHIP_EXCLUSION_LABEL):
                    print(f"\tPR #{pr_number}: Removing '{AUTHOR_MEMBERSHIP_EXCLUSION_LABEL}' label due to trigger comment")
                    remove_label(pr_number, AUTHOR_MEMBERSHIP_EXCLUSION_LABEL)

                if not author_in_org and not has_comment:
                    print(f"\tSkipping PR #{pr_number}: Author {pr['user']['login']} is not in {ORG_NAME} and is missing comment trigger")
                    
                    # Apply exclusion label if not already present
                    if not has_label(pr_number, AUTHOR_MEMBERSHIP_EXCLUSION_LABEL):
                        print(f"\tPR #{pr_number} doesn't have the '{AUTHOR_MEMBERSHIP_EXCLUSION_LABEL}' label. Applying...")
                        apply_label(pr_number, AUTHOR_MEMBERSHIP_EXCLUSION_LABEL)
                    
                    process_pr = False

        if not process_pr:
            continue

        # Get the latest commit SHA directly from the PR data
        latest_sha = pr['head']['sha']
        print(f"\tLatest commit SHA: {latest_sha}")

        # Check if required checks have completed (if flag is set)
        if CHECK_ACTION_COMPLETION:
            if not has_required_action_completed(latest_sha, REQUIRED_CHECK_NAME, REQUIRED_CHECK_CONCLUSION):
                print(
                    f"\tSkipping PR #{pr_number}: Required check '{REQUIRED_CHECK_NAME}' has not completed with conclusion '{REQUIRED_CHECK_CONCLUSION}'")
                continue

        files = get_files_for_pull_request(pr_number)

        # Check if PR has too many rules and should be skipped
        if SKIP_BULK_PRS:
            yaml_rule_count = count_yaml_rules_in_pr(files)
            if yaml_rule_count > MAX_RULES_PER_PR:
                print(f"\tSkipping PR #{pr_number}: Contains {yaml_rule_count} YAML rules (max allowed: {MAX_RULES_PER_PR})")
                
                # Apply label to indicate PR was skipped due to too many rules
                if not has_label(pr_number, BULK_PR_LABEL):
                    print(f"\tPR #{pr_number} doesn't have the '{BULK_PR_LABEL}' label. Applying...")
                    apply_label(pr_number, BULK_PR_LABEL)
                
                continue

        # Process files in the PR
        for file in files:
            print(f"\tStatus of {file['filename']}: {file['status']}")
            process_file = False

            # Common file type and status check
            if file['status'] in ['added', 'modified', 'changed'] and file['filename'].startswith(
                    'detection-rules/') and file['filename'].endswith('.yml'):
                if file['status'] == "added" and INCLUDE_ADDED:
                    process_file = True
                elif file['status'] in ['modified', 'changed'] and INCLUDE_UPDATES:
                    process_file = True
                else:
                    print(
                        f"\tSkipping {file['status']} file: {file['filename']} in PR #{pr['number']} -- INCLUDE_UPDATES == {INCLUDE_UPDATES}, INCLUDE_ADDED == {INCLUDE_ADDED}")
            else:
                print(
                    f"\tSkipping {file['status']} file: {file['filename']} in PR #{pr['number']} -- unmanaged file status")

            # If file should be processed, get content and apply mode-specific logic
            if process_file:
                content = get_file_contents(file['contents_url'])

                # Skip files with specific text if flag is set
                if SKIP_FILES_WITH_TEXT and SKIP_TEXTS:
                    matched_texts, labels_to_apply = check_skip_texts(content, SKIP_TEXTS)
                    if matched_texts:
                        print(f"\tSkipping file {file['filename']}: contains texts {matched_texts}")

                        # Apply all associated labels
                        for label in labels_to_apply:
                            if not has_label(pr_number, label):
                                print(f"\tPR #{pr_number} doesn't have the '{label}' label. Applying...")
                                apply_label(pr_number, label)

                        continue

                # Process file (common for both modes)
                target_save_filename = f"{pr['number']}_{os.path.basename(file['filename'])}"

                # Get the modified content and original ID
                modified_content, original_id = add_id_to_yaml(content, target_save_filename)

                # Test-rules mode: add special fields
                if mode == 'test-rules':
                    # Store the original id
                    if original_id:
                        modified_content = modified_content.rstrip()
                        modified_content += f"\nog_id: \"{original_id}\""

                    # Add the PR number as testing_pr
                    modified_content = modified_content.rstrip()
                    modified_content += f"\ntesting_pr: {pr_number}"

                    # Add the commit SHA as testing_sha
                    modified_content = modified_content.rstrip()
                    modified_content += f"\ntesting_sha: {latest_sha}"

                # Common modifications based on flags
                if ADD_AUTHOR_TAG:
                    modified_content = add_block(modified_content, 'tags', f"{AUTHOR_TAG_PREFIX}{pr['user']['login']}")

                # Add open PR tag if flag is set
                if CREATE_OPEN_PR_TAG:
                    modified_content = add_block(modified_content, 'tags', OPEN_PR_TAG)

                if ADD_RULE_STATUS_TAG:
                    modified_content = add_block(modified_content, 'tags', f"{RULE_STATUS_PREFIX}{file['status']}")

                if ADD_PR_REFERENCE:
                    modified_content = add_block(modified_content, 'references', pr['html_url'])

                # In standard mode, always include PR in name (required for handle_closed_prs)
                # In test-rules mode, never include PR in name
                if mode == 'standard':
                    modified_content = rename_rules(modified_content, pr)

                # Save the file
                save_file(target_save_filename, modified_content)
                new_files.add(target_save_filename)
                print(f"\tSaved: {target_save_filename}")

                # apply the label
                if mode == 'test-rules' and ADD_TEST_RULES_LABEL:
                    # Check if PR already has the label
                    if not has_label(pr_number, IN_TEST_RULES_LABEL):
                        print(f"\tPR #{pr_number} doesn't have the '{IN_TEST_RULES_LABEL}' label. Applying...")
                        apply_label(pr_number, IN_TEST_RULES_LABEL)

    # Clean up files no longer in open PRs
    clean_output_folder(new_files)
    return new_files


if __name__ == '__main__':
    sublime_header = [
        ' ______     __  __     ______     __         __     __    __     ______    ',
        '/\\  ___\\   /\\ \\ /\\ \\   /\\  == \\   /\\ \\       /\\ \\   /\\ "-./  \\   /\\  ___\\   ',
        '\\ \\___  \\  \\ \\ \\_\\ \\  \\ \\  __<   \\ \\ \\____  \\ \\ \\  \\ \\ \\-./\\ \\  \\ \\  __\\   ',
        ' \\/\\_____\\  \\ \\_____\\  \\ \\_____\\  \\ \\_____\\  \\ \\_\\  \\ \\_\\ \\ \\_\\  \\ \\_____\\ ',
        '  \\/_____/   \\/_____/   \\/_____/   \\/_____/   \\/_/   \\/_/  \\/_/   \\/_____/ ',
        '                                                                           ',
    ]

    for line in sublime_header:
        print(line)

    # Determine which functions to run based on SCRIPT_MODE
    if SCRIPT_MODE == 'standard':
        print("Running in standard mode...")
        handle_pr_rules('standard')
        handle_closed_prs()

    elif SCRIPT_MODE == 'test-rules':
        print("Running in test-rules mode...")
        handle_pr_rules('test-rules')

    else:
        print(f"Error: Unknown SCRIPT_MODE '{SCRIPT_MODE}'. Valid options are 'standard' or 'test-rules'.")
        exit(1)
