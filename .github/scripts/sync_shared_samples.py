#!/usr/bin/env python3
"""
Sync Shared Samples Script

Syncs detection rules from open PRs to the shared-samples branch.
This script handles:
- File-based syncing to shared-samples branch
- PR# prefix in rule names
- Author tags and references
- Closed PR rule deletion via Sublime API (after delay)
- Bulk PR limits

Uses GraphQL for bulk data fetching (~95% reduction in API calls).
"""
import os
import sys
from datetime import datetime, timedelta, timezone
from urllib.parse import quote

import requests

# Add the lib directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from lib import (
    # Constants
    DO_NOT_MERGE_LABEL,
    SHARED_SAMPLES_BULK_PR_LABEL,
    SHARED_SAMPLES_AUTHOR_MEMBERSHIP_EXCLUSION_LABEL,
    DEFAULT_MAX_RULES_PER_PR,
    DEFAULT_DELETE_RULES_DELAY_DAYS,
    DEFAULT_AUTHOR_TAG_PREFIX,
    DEFAULT_RULE_STATUS_PREFIX,
    DEFAULT_OPEN_PR_TAG,
    DEFAULT_REQUIRED_CHECK_NAME,
    DEFAULT_REQUIRED_CHECK_CONCLUSION,
    DEFAULT_ORG_NAME,
    DEFAULT_COMMENT_TRIGGER,
    # GraphQL
    create_graphql_session,
    fetch_all_prs,
    # REST (for writes)
    create_github_session,
    apply_label,
    remove_label,
    # Utilities
    add_id_to_yaml,
    add_block,
    rename_rules,
    get_file_contents,
    save_file,
    clean_output_folder,
    post_exclusion_comment_if_needed,
)

# Configuration from environment
GITHUB_TOKEN = os.getenv('GITHUB_TOKEN')
SUBLIME_API_TOKEN = os.getenv('SUBLIME_API_TOKEN')
REPO_OWNER = os.getenv('REPO_OWNER', 'sublime-security')
REPO_NAME = os.getenv('REPO_NAME', 'sublime-rules')
OUTPUT_FOLDER = os.getenv('OUTPUT_FOLDER', 'detection-rules')

# Feature flags
ADD_AUTHOR_TAG = os.getenv('ADD_AUTHOR_TAG', 'true').lower() == 'true'
AUTHOR_TAG_PREFIX = os.getenv('AUTHOR_TAG_PREFIX', DEFAULT_AUTHOR_TAG_PREFIX)
ADD_RULE_STATUS_TAG = os.getenv('ADD_RULE_STATUS_TAG', 'true').lower() == 'true'
RULE_STATUS_PREFIX = os.getenv('RULE_STATUS_PREFIX', DEFAULT_RULE_STATUS_PREFIX)
ADD_PR_REFERENCE = os.getenv('ADD_PR_REFERENCE', 'true').lower() == 'true'
CREATE_OPEN_PR_TAG = os.getenv('CREATE_OPEN_PR_TAG', 'true').lower() == 'true'
OPEN_PR_TAG = os.getenv('OPEN_PR_TAG', DEFAULT_OPEN_PR_TAG)

# File inclusion flags
INCLUDE_ADDED = os.getenv('INCLUDE_ADDED', 'true').lower() == 'true'
INCLUDE_UPDATES = os.getenv('INCLUDE_UPDATES', 'true').lower() == 'true'

# Closed PR handling
DELETE_RULES_FROM_CLOSED_PRS = os.getenv('DELETE_RULES_FROM_CLOSED_PRS', 'true').lower() == 'true'
DELETE_RULES_FROM_CLOSED_PRS_DELAY = int(os.getenv('DELETE_RULES_FROM_CLOSED_PRS_DELAY', str(DEFAULT_DELETE_RULES_DELAY_DAYS)))

# Organization membership filtering
FILTER_BY_ORG_MEMBERSHIP = os.getenv('FILTER_BY_ORG_MEMBERSHIP', 'true').lower() == 'true'
ORG_NAME = os.getenv('ORG_NAME', DEFAULT_ORG_NAME)
INCLUDE_PRS_WITH_COMMENT = os.getenv('INCLUDE_PRS_WITH_COMMENT', 'true').lower() == 'true'
COMMENT_TRIGGER = os.getenv('COMMENT_TRIGGER', DEFAULT_COMMENT_TRIGGER)

# Bulk PR limits
SKIP_BULK_PRS = os.getenv('SKIP_BULK_PRS', 'true').lower() == 'true'
MAX_RULES_PER_PR = int(os.getenv('MAX_RULES_PER_PR', str(DEFAULT_MAX_RULES_PER_PR)))

# Action completion checks
CHECK_ACTION_COMPLETION = os.getenv('CHECK_ACTION_COMPLETION', 'true').lower() == 'true'
REQUIRED_CHECK_NAME = os.getenv('REQUIRED_CHECK_NAME', DEFAULT_REQUIRED_CHECK_NAME)
REQUIRED_CHECK_CONCLUSION = os.getenv('REQUIRED_CHECK_CONCLUSION', DEFAULT_REQUIRED_CHECK_CONCLUSION)

# Create output folder if it doesn't exist
if not os.path.exists(OUTPUT_FOLDER):
    os.makedirs(OUTPUT_FOLDER)


def search_sublime_rule_feed(rule_name):
    """
    Search for rules in the Sublime rule feed by name.

    Args:
        rule_name (str): Rule name to search for

    Returns:
        dict: Search results or None on error
    """
    # Strip quotes for searching
    rule_name = rule_name.strip("\"'")
    rule_name = quote(rule_name)
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
        return None
    except requests.exceptions.ConnectionError as err:
        print(f"Connection error occurred: {err}")
        return None
    else:
        print(f"\tSearch Feed Response Code: {response.status_code}")
        response = response.json()
        print(f"\tSearch Feed Found Count: {response['count']}")
        return response


def sublime_delete_rule(rule_id):
    """
    Delete a rule from the Sublime platform.

    Args:
        rule_id (str): Rule ID to delete

    Returns:
        bool: True if deletion was successful
    """
    url = f"https://platform.sublime.security/v0/rules/{rule_id}"

    headers = {
        "accept": "application/json",
        "authorization": f"Bearer {SUBLIME_API_TOKEN}"
    }
    response = requests.delete(url, headers=headers)

    print(f"\tDelete Rule Response Code: {response.status_code}")

    return response.ok


def handle_closed_prs(graphql_session):
    """
    Handle closed PRs by deleting rules from closed PRs after a delay period.
    Uses comprehensive search by PR number pattern to catch all rules including orphaned ones.

    Uses GraphQL for efficient bulk fetching of closed PRs.

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

    # Fetch closed PRs via GraphQL (limit to 60 for efficiency)
    closed_pull_requests = fetch_all_prs(
        graphql_session, REPO_OWNER, REPO_NAME,
        states=['CLOSED', 'MERGED'],
        max_results=60
    )

    for closed_pr in closed_pull_requests:
        pr_number = closed_pr.number
        print(f"Processing CLOSED PR #{pr_number}: {closed_pr.title}")

        if closed_pr.base_ref != "main":
            print(f"\tSkipping non-main branch PR #{closed_pr.number}: {closed_pr.title} -- dest branch: {closed_pr.base_ref}")
            continue

        # Check delay for merged PRs
        if closed_pr.merged_at is not None:
            merged_at_time = datetime.fromisoformat(closed_pr.merged_at.replace("Z", "+00:00"))

            if not merged_at_time <= datetime.now(tz=timezone.utc) - timedelta(days=DELETE_RULES_FROM_CLOSED_PRS_DELAY):
                time_remaining = (merged_at_time + timedelta(days=DELETE_RULES_FROM_CLOSED_PRS_DELAY)) - datetime.now(tz=timezone.utc)

                remaining_days = time_remaining.days
                remaining_hours, remaining_remainder = divmod(time_remaining.seconds, 3600)
                remaining_minutes, remaining_seconds = divmod(remaining_remainder, 60)

                print(f"\tDELAY NOT MET: Skipping PR #{closed_pr.number}: {closed_pr.title}\n\tRemaining Time = {remaining_days} days, {remaining_hours} hours, {remaining_minutes} minutes, {remaining_seconds} seconds")
                continue

        # Search for all rules with this PR number pattern
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

            # Verify this rule actually belongs to this PR
            if not rule_name.startswith(pr_search_pattern):
                print(f"\tSkipping rule '{rule_name}' - doesn't match expected pattern")
                continue

            print(f"\tEvaluating rule: {rule_name}")

            # Verify this rule has the expected tags
            rule_tags = found_rule.get('tags', [])

            # Check for the open PR tag
            if CREATE_OPEN_PR_TAG and OPEN_PR_TAG not in rule_tags:
                print(f"\t\tSkipping rule - missing required tag '{OPEN_PR_TAG}'")
                continue

            # Check for the author tag if enabled
            if ADD_AUTHOR_TAG:
                expected_author_tag = f"{AUTHOR_TAG_PREFIX}{closed_pr.author_login}"
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


def handle_pr_rules(graphql_session, rest_session):
    """
    Process open PRs to sync rules to shared-samples branch.

    Uses GraphQL for bulk data fetching, REST for file contents and writes.

    Args:
        graphql_session: GitHub GraphQL API session for bulk reads
        rest_session: GitHub REST API session for file contents and write operations

    Returns:
        set: Set of filenames that were processed
    """
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

    for line in header:
        print(line)

    # Fetch ALL open PRs with labels, files, comments, and checks in 1-2 API calls
    pull_requests = fetch_all_prs(graphql_session, REPO_OWNER, REPO_NAME, states=['OPEN'])
    new_files = set()

    for pr in pull_requests:
        pr_number = pr.number

        # Check for do-not-merge label - skip entirely if present
        if pr.has_label(DO_NOT_MERGE_LABEL):
            print(f"Skipping PR #{pr_number} (has '{DO_NOT_MERGE_LABEL}' label): {pr.title}")
            continue

        # Skip draft PRs
        if pr.is_draft:
            print(f"Skipping draft PR #{pr_number}: {pr.title}")
            continue

        # Skip non-main PRs
        if pr.base_ref != 'main':
            print(f"Skipping non-main branch PR #{pr_number}: {pr.title} -- dest branch: {pr.base_ref}")
            continue

        # Organization membership and comment trigger checks
        process_pr = True
        print(f"Processing PR #{pr_number}: {pr.title}")

        if FILTER_BY_ORG_MEMBERSHIP:
            # Use authorAssociation instead of REST API org membership check
            author_in_org = pr.is_author_org_member()
            has_comment = False

            if author_in_org:
                print(f"\tPR #{pr_number}: Author {pr.author_login} is an org member (association: {pr.author_association})")
                # Remove exclusion label if present
                if pr.has_label(SHARED_SAMPLES_AUTHOR_MEMBERSHIP_EXCLUSION_LABEL):
                    remove_label(rest_session, REPO_OWNER, REPO_NAME, pr_number, SHARED_SAMPLES_AUTHOR_MEMBERSHIP_EXCLUSION_LABEL)
            else:
                # Check for trigger comment if author not in org (in-memory check)
                if INCLUDE_PRS_WITH_COMMENT:
                    has_comment = pr.has_trigger_comment(COMMENT_TRIGGER)

                    # If trigger comment was found, remove the exclusion label
                    if has_comment and pr.has_label(SHARED_SAMPLES_AUTHOR_MEMBERSHIP_EXCLUSION_LABEL):
                        print(f"\tPR #{pr_number}: Removing '{SHARED_SAMPLES_AUTHOR_MEMBERSHIP_EXCLUSION_LABEL}' label due to trigger comment")
                        remove_label(rest_session, REPO_OWNER, REPO_NAME, pr_number, SHARED_SAMPLES_AUTHOR_MEMBERSHIP_EXCLUSION_LABEL)

                    if not has_comment:
                        print(f"\tSkipping PR #{pr_number}: Author {pr.author_login} is not an org member and is missing comment trigger")

                        # Apply exclusion label if not already present
                        if not pr.has_label(SHARED_SAMPLES_AUTHOR_MEMBERSHIP_EXCLUSION_LABEL):
                            print(f"\tPR #{pr_number} doesn't have the '{SHARED_SAMPLES_AUTHOR_MEMBERSHIP_EXCLUSION_LABEL}' label. Applying...")
                            apply_label(rest_session, REPO_OWNER, REPO_NAME, pr_number, SHARED_SAMPLES_AUTHOR_MEMBERSHIP_EXCLUSION_LABEL)
                            # Post comment explaining how to enable sync
                            post_exclusion_comment_if_needed(
                                rest_session, REPO_OWNER, REPO_NAME, pr_number,
                                SHARED_SAMPLES_AUTHOR_MEMBERSHIP_EXCLUSION_LABEL,
                                org_name=ORG_NAME,
                                comment_trigger=COMMENT_TRIGGER
                            )

                        process_pr = False

        if not process_pr:
            continue

        # Get the latest commit SHA
        latest_sha = pr.head_sha
        print(f"\tLatest commit SHA: {latest_sha}")

        # Check if required checks have completed (in-memory check)
        if CHECK_ACTION_COMPLETION:
            if not pr.has_required_check(REQUIRED_CHECK_NAME, REQUIRED_CHECK_CONCLUSION):
                print(f"\tSkipping PR #{pr_number}: Required check '{REQUIRED_CHECK_NAME}' has not completed with conclusion '{REQUIRED_CHECK_CONCLUSION}'")
                # Preserve existing synced files from previous passing commits
                prefix = f"{pr_number}_"
                for filename in os.listdir(OUTPUT_FOLDER):
                    if filename.startswith(prefix) and filename.endswith('.yml'):
                        print(f"\tPreserving existing file: {filename}")
                        new_files.add(filename)
                continue

        # Use files from GraphQL data (already fetched)
        files = pr.files

        # Check if PR has too many rules
        if SKIP_BULK_PRS:
            yaml_rule_count = pr.count_yaml_rules()
            if yaml_rule_count > MAX_RULES_PER_PR:
                print(f"\tSkipping PR #{pr_number}: Contains {yaml_rule_count} YAML rules (max allowed: {MAX_RULES_PER_PR})")

                # Apply bulk label if not already present
                if not pr.has_label(SHARED_SAMPLES_BULK_PR_LABEL):
                    print(f"\tPR #{pr_number} doesn't have the '{SHARED_SAMPLES_BULK_PR_LABEL}' label. Applying...")
                    apply_label(rest_session, REPO_OWNER, REPO_NAME, pr_number, SHARED_SAMPLES_BULK_PR_LABEL)
                    # Post comment explaining the limit
                    post_exclusion_comment_if_needed(
                        rest_session, REPO_OWNER, REPO_NAME, pr_number,
                        SHARED_SAMPLES_BULK_PR_LABEL,
                        max_rules=MAX_RULES_PER_PR,
                        rule_count=yaml_rule_count
                    )

                continue
            else:
                # Remove bulk label if rule count is now under limit
                if pr.has_label(SHARED_SAMPLES_BULK_PR_LABEL):
                    remove_label(rest_session, REPO_OWNER, REPO_NAME, pr_number, SHARED_SAMPLES_BULK_PR_LABEL)

        # Process files in the PR
        for file in files:
            print(f"\tStatus of {file['filename']}: {file['status']}")
            process_file = False

            # Check file type and status
            if (file['status'] in ['added', 'modified', 'changed'] and
                file['filename'].startswith('detection-rules/') and
                    file['filename'].endswith('.yml')):
                if file['status'] == "added" and INCLUDE_ADDED:
                    process_file = True
                elif file['status'] in ['modified', 'changed'] and INCLUDE_UPDATES:
                    process_file = True
                else:
                    print(f"\tSkipping {file['status']} file: {file['filename']} in PR #{pr_number} -- INCLUDE_UPDATES == {INCLUDE_UPDATES}, INCLUDE_ADDED == {INCLUDE_ADDED}")
            else:
                print(f"\tSkipping {file['status']} file: {file['filename']} in PR #{pr_number} -- unmanaged file status")

            if process_file:
                # Fetch file content (still REST - only for filtered PRs)
                content = get_file_contents(
                    rest_session, REPO_OWNER, REPO_NAME,
                    file['filename'], latest_sha
                )

                # Process the file
                target_save_filename = f"{pr_number}_{os.path.basename(file['filename'])}"

                # Get modified content and original ID
                modified_content, original_id = add_id_to_yaml(content, target_save_filename)

                # Add author tag if enabled
                if ADD_AUTHOR_TAG:
                    modified_content = add_block(modified_content, 'tags', f"{AUTHOR_TAG_PREFIX}{pr.author_login}")

                # Add open PR tag if enabled
                if CREATE_OPEN_PR_TAG:
                    modified_content = add_block(modified_content, 'tags', OPEN_PR_TAG)

                # Add rule status tag if enabled
                if ADD_RULE_STATUS_TAG:
                    modified_content = add_block(modified_content, 'tags', f"{RULE_STATUS_PREFIX}{file['status']}")

                # Add PR reference if enabled
                if ADD_PR_REFERENCE:
                    modified_content = add_block(modified_content, 'references', pr.url)

                # Create a PR-like dict for rename_rules compatibility
                pr_dict = {
                    'number': pr.number,
                    'title': pr.title,
                }

                # Always rename rules with PR# prefix (required for handle_closed_prs)
                modified_content = rename_rules(modified_content, pr_dict)

                # Save the file
                save_file(OUTPUT_FOLDER, target_save_filename, modified_content)
                new_files.add(target_save_filename)
                print(f"\tSaved: {target_save_filename}")

    # Clean up files no longer in open PRs
    clean_output_folder(OUTPUT_FOLDER, new_files)
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

    print("Running shared-samples sync...")
    graphql_session = create_graphql_session(GITHUB_TOKEN)
    rest_session = create_github_session(GITHUB_TOKEN)
    handle_pr_rules(graphql_session, rest_session)
    handle_closed_prs(graphql_session)
