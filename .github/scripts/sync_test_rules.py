#!/usr/bin/env python3
"""
Sync Test Rules Script

Syncs detection rules from open PRs to the test-rules branch.
This script handles test-rules specific logic including:
- Draft PR handling with label/comment triggers
- Organization membership filtering
- Bulk PR limits
- Link analysis exclusions
- PR commenting for exclusions
"""
import os
import sys

# Add the lib directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from lib import (
    # Constants
    IN_TEST_RULES_LABEL,
    AUTHOR_MEMBERSHIP_EXCLUSION_LABEL,
    MANUAL_EXCLUSION_LABEL,
    BULK_PR_LABEL,
    DO_NOT_MERGE_LABEL,
    SKIP_TEXTS,
    DEFAULT_ORG_NAME,
    DEFAULT_COMMENT_TRIGGER,
    DEFAULT_MAX_RULES_PER_PR,
    DEFAULT_REQUIRED_CHECK_NAME,
    DEFAULT_REQUIRED_CHECK_CONCLUSION,
    # Functions
    create_github_session,
    has_label,
    apply_label,
    remove_label,
    is_user_in_org,
    has_trigger_comment,
    has_required_action_completed,
    check_skip_texts,
    add_id_to_yaml,
    add_block,
    get_file_contents,
    save_file,
    pr_has_synced_files,
    clean_output_folder,
    count_yaml_rules_in_pr,
    post_exclusion_comment_if_needed,
)

# Configuration from environment
GITHUB_TOKEN = os.getenv('GITHUB_TOKEN')
REPO_OWNER = os.getenv('REPO_OWNER', 'sublime-security')
REPO_NAME = os.getenv('REPO_NAME', 'sublime-rules')
OUTPUT_FOLDER = os.getenv('OUTPUT_FOLDER', 'detection-rules')

# Test-rules specific configuration
FILTER_BY_ORG_MEMBERSHIP = os.getenv('FILTER_BY_ORG_MEMBERSHIP', 'true').lower() == 'true'
ORG_NAME = os.getenv('ORG_NAME', DEFAULT_ORG_NAME)
INCLUDE_PRS_WITH_COMMENT = os.getenv('INCLUDE_PRS_WITH_COMMENT', 'true').lower() == 'true'
COMMENT_TRIGGER = os.getenv('COMMENT_TRIGGER', DEFAULT_COMMENT_TRIGGER)

# File filtering
SKIP_FILES_WITH_TEXT = os.getenv('SKIP_FILES_WITH_TEXT', 'true').lower() == 'true'

# Bulk PR limits
SKIP_BULK_PRS = os.getenv('SKIP_BULK_PRS', 'true').lower() == 'true'
MAX_RULES_PER_PR = int(os.getenv('MAX_RULES_PER_PR', str(DEFAULT_MAX_RULES_PER_PR)))

# Action completion checks
CHECK_ACTION_COMPLETION = os.getenv('CHECK_ACTION_COMPLETION', 'true').lower() == 'true'
REQUIRED_CHECK_NAME = os.getenv('REQUIRED_CHECK_NAME', DEFAULT_REQUIRED_CHECK_NAME)
REQUIRED_CHECK_CONCLUSION = os.getenv('REQUIRED_CHECK_CONCLUSION', DEFAULT_REQUIRED_CHECK_CONCLUSION)

# Labeling
ADD_TEST_RULES_LABEL = os.getenv('ADD_TEST_RULES_LABEL', 'true').lower() == 'true'

# Feature flags from original script (all disabled for test-rules mode)
INCLUDE_ADDED = os.getenv('INCLUDE_ADDED', 'true').lower() == 'true'
INCLUDE_UPDATES = os.getenv('INCLUDE_UPDATES', 'true').lower() == 'true'

# Create output folder if it doesn't exist
if not os.path.exists(OUTPUT_FOLDER):
    os.makedirs(OUTPUT_FOLDER)


def get_open_pull_requests(session):
    """Fetch all open pull requests from the repository."""
    pull_requests = []
    page = 1
    per_page = 30

    while True:
        url = f'https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/pulls'
        params = {'page': page, 'per_page': per_page, 'sort': 'updated', 'direction': 'desc'}
        print(f"Fetching page {page} of Pull Requests")
        response = session.get(url, params=params)
        response.raise_for_status()

        pull_requests.extend(response.json())

        if 'Link' in response.headers:
            links = response.headers['Link'].split(', ')
            has_next = any('rel="next"' in link for link in links)
        else:
            has_next = False

        if not has_next:
            print(f"Fetched page {page} of Pull Requests")
            print(f"PRs on page {page}: {len(response.json())}")
            break

        print(f"Fetched page {page} of Pull Requests")
        print(f"PRs on page {page}: {len(response.json())}")
        print(f"PRs found so far: {len(pull_requests)}")
        print(f"Moving to page {page + 1}")
        page += 1

    print(f"Total PRs: {len(pull_requests)}")
    return pull_requests


def get_files_for_pull_request(session, pr_number):
    """Fetch files changed in a pull request."""
    url = f'https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/pulls/{pr_number}/files'
    response = session.get(url)
    response.raise_for_status()
    return response.json()


def handle_pr_rules(session):
    """
    Process open PRs to sync rules to test-rules branch.

    Returns:
        set: Set of filenames that were processed
    """
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

    pull_requests = get_open_pull_requests(session)
    new_files = set()

    for pr in pull_requests:
        pr_number = pr['number']

        # Check for do-not-merge label first - skip entirely if present
        if has_label(session, REPO_OWNER, REPO_NAME, pr_number, DO_NOT_MERGE_LABEL):
            print(f"Skipping PR #{pr_number} (has '{DO_NOT_MERGE_LABEL}' label): {pr['title']}")
            continue

        # Draft PR handling
        if pr['draft']:
            # Process drafts if they have in-test-rules label OR trigger comment
            has_in_test_rules = has_label(session, REPO_OWNER, REPO_NAME, pr_number, IN_TEST_RULES_LABEL)
            has_comment = False

            if INCLUDE_PRS_WITH_COMMENT and not has_in_test_rules:
                # Check for trigger comment from org member
                has_comment = has_trigger_comment(
                    session, REPO_OWNER, REPO_NAME, pr_number, ORG_NAME, COMMENT_TRIGGER
                )
                if has_comment:
                    # Apply the in-test-rules label since trigger comment was found
                    print(f"\tDraft PR #{pr_number} has trigger comment, applying '{IN_TEST_RULES_LABEL}' label")
                    apply_label(session, REPO_OWNER, REPO_NAME, pr_number, IN_TEST_RULES_LABEL)

            if has_in_test_rules or has_comment:
                print(f"Processing draft PR #{pr_number} (has '{IN_TEST_RULES_LABEL}' label or trigger comment): {pr['title']}")
            else:
                print(f"Skipping draft PR #{pr_number}: {pr['title']}")
                continue

        # Skip PRs not targeting main
        if pr['base']['ref'] != 'main':
            print(f"Skipping non-main branch PR #{pr_number}: {pr['title']} -- dest branch: {pr['base']['ref']}")
            continue

        # Check for manual exclusion label (user opted out of test-rules)
        if has_label(session, REPO_OWNER, REPO_NAME, pr_number, MANUAL_EXCLUSION_LABEL):
            print(f"Skipping manually excluded PR #{pr_number}: {pr['title']}")
            # Remove in-test-rules label if both are present (manual exclusion takes precedence)
            if has_label(session, REPO_OWNER, REPO_NAME, pr_number, IN_TEST_RULES_LABEL):
                print(f"\tRemoving '{IN_TEST_RULES_LABEL}' label since manual exclusion takes precedence")
                remove_label(session, REPO_OWNER, REPO_NAME, pr_number, IN_TEST_RULES_LABEL)
            continue

        # Check if user removed the in-test-rules label (opt-out)
        if pr_has_synced_files(OUTPUT_FOLDER, pr_number) and not has_label(session, REPO_OWNER, REPO_NAME, pr_number, IN_TEST_RULES_LABEL):
            print(f"PR #{pr_number} has synced files but '{IN_TEST_RULES_LABEL}' label was removed - applying manual exclusion")
            apply_label(session, REPO_OWNER, REPO_NAME, pr_number, MANUAL_EXCLUSION_LABEL)
            continue

        # Organization membership and comment trigger checks
        process_pr = True
        print(f"Processing PR #{pr_number}: {pr['title']}")

        if FILTER_BY_ORG_MEMBERSHIP:
            author_in_org = is_user_in_org(session, pr['user']['login'], ORG_NAME)
            has_comment = False

            if author_in_org:
                print(f"\tPR #{pr_number}: Author {pr['user']['login']} is in {ORG_NAME}")
                # Remove exclusion label if present
                if has_label(session, REPO_OWNER, REPO_NAME, pr_number, AUTHOR_MEMBERSHIP_EXCLUSION_LABEL):
                    remove_label(session, REPO_OWNER, REPO_NAME, pr_number, AUTHOR_MEMBERSHIP_EXCLUSION_LABEL)
            else:
                # Check for trigger comment if author not in org
                if INCLUDE_PRS_WITH_COMMENT:
                    has_comment = has_trigger_comment(
                        session, REPO_OWNER, REPO_NAME, pr_number, ORG_NAME, COMMENT_TRIGGER
                    )

                    # If trigger comment was found, remove the exclusion label
                    if has_comment and has_label(session, REPO_OWNER, REPO_NAME, pr_number, AUTHOR_MEMBERSHIP_EXCLUSION_LABEL):
                        print(f"\tPR #{pr_number}: Removing '{AUTHOR_MEMBERSHIP_EXCLUSION_LABEL}' label due to trigger comment")
                        remove_label(session, REPO_OWNER, REPO_NAME, pr_number, AUTHOR_MEMBERSHIP_EXCLUSION_LABEL)

                    if not has_comment:
                        print(f"\tSkipping PR #{pr_number}: Author {pr['user']['login']} is not in {ORG_NAME} and is missing comment trigger")

                        # Apply exclusion label if not already present
                        if not has_label(session, REPO_OWNER, REPO_NAME, pr_number, AUTHOR_MEMBERSHIP_EXCLUSION_LABEL):
                            print(f"\tPR #{pr_number} doesn't have the '{AUTHOR_MEMBERSHIP_EXCLUSION_LABEL}' label. Applying...")
                            apply_label(session, REPO_OWNER, REPO_NAME, pr_number, AUTHOR_MEMBERSHIP_EXCLUSION_LABEL)
                            # Post comment explaining how to enable sync
                            post_exclusion_comment_if_needed(
                                session, REPO_OWNER, REPO_NAME, pr_number,
                                AUTHOR_MEMBERSHIP_EXCLUSION_LABEL,
                                org_name=ORG_NAME,
                                comment_trigger=COMMENT_TRIGGER
                            )

                        # Remove in-test-rules label if previously applied
                        if has_label(session, REPO_OWNER, REPO_NAME, pr_number, IN_TEST_RULES_LABEL):
                            remove_label(session, REPO_OWNER, REPO_NAME, pr_number, IN_TEST_RULES_LABEL)

                        process_pr = False

        if not process_pr:
            continue

        # Get the latest commit SHA
        latest_sha = pr['head']['sha']
        print(f"\tLatest commit SHA: {latest_sha}")

        # Check if required checks have completed
        if CHECK_ACTION_COMPLETION:
            if not has_required_action_completed(
                session, REPO_OWNER, REPO_NAME, latest_sha,
                REQUIRED_CHECK_NAME, REQUIRED_CHECK_CONCLUSION
            ):
                print(f"\tSkipping PR #{pr_number}: Required check '{REQUIRED_CHECK_NAME}' has not completed with conclusion '{REQUIRED_CHECK_CONCLUSION}'")
                # Remove in-test-rules label if previously applied
                if has_label(session, REPO_OWNER, REPO_NAME, pr_number, IN_TEST_RULES_LABEL):
                    remove_label(session, REPO_OWNER, REPO_NAME, pr_number, IN_TEST_RULES_LABEL)
                continue

        files = get_files_for_pull_request(session, pr_number)

        # Check if PR has too many rules
        if SKIP_BULK_PRS:
            yaml_rule_count = count_yaml_rules_in_pr(files)
            if yaml_rule_count > MAX_RULES_PER_PR:
                print(f"\tSkipping PR #{pr_number}: Contains {yaml_rule_count} YAML rules (max allowed: {MAX_RULES_PER_PR})")

                # Apply label if not already present
                if not has_label(session, REPO_OWNER, REPO_NAME, pr_number, BULK_PR_LABEL):
                    print(f"\tPR #{pr_number} doesn't have the '{BULK_PR_LABEL}' label. Applying...")
                    apply_label(session, REPO_OWNER, REPO_NAME, pr_number, BULK_PR_LABEL)
                    # Post comment explaining the limit
                    post_exclusion_comment_if_needed(
                        session, REPO_OWNER, REPO_NAME, pr_number,
                        BULK_PR_LABEL,
                        max_rules=MAX_RULES_PER_PR,
                        rule_count=yaml_rule_count
                    )

                # Remove in-test-rules label if previously applied
                if has_label(session, REPO_OWNER, REPO_NAME, pr_number, IN_TEST_RULES_LABEL):
                    remove_label(session, REPO_OWNER, REPO_NAME, pr_number, IN_TEST_RULES_LABEL)

                continue
            else:
                # Remove bulk label if rule count is now under limit
                if has_label(session, REPO_OWNER, REPO_NAME, pr_number, BULK_PR_LABEL):
                    remove_label(session, REPO_OWNER, REPO_NAME, pr_number, BULK_PR_LABEL)

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
                # Fetch file content
                content = get_file_contents(
                    session, REPO_OWNER, REPO_NAME,
                    file['filename'], latest_sha
                )

                # Skip files with specific text patterns
                if SKIP_FILES_WITH_TEXT and SKIP_TEXTS:
                    matched_texts, labels_to_apply = check_skip_texts(content, SKIP_TEXTS)
                    if matched_texts:
                        print(f"\tSkipping file {file['filename']}: contains texts {matched_texts}")

                        # Apply all associated labels
                        for label in labels_to_apply:
                            if not has_label(session, REPO_OWNER, REPO_NAME, pr_number, label):
                                print(f"\tPR #{pr_number} doesn't have the '{label}' label. Applying...")
                                apply_label(session, REPO_OWNER, REPO_NAME, pr_number, label)

                        # Post comment for link_analysis exclusion
                        from lib.constants import LINK_ANALYSIS_EXCLUSION_LABEL
                        if LINK_ANALYSIS_EXCLUSION_LABEL in labels_to_apply:
                            post_exclusion_comment_if_needed(
                                session, REPO_OWNER, REPO_NAME, pr_number,
                                LINK_ANALYSIS_EXCLUSION_LABEL
                            )

                        # Remove in-test-rules label
                        if has_label(session, REPO_OWNER, REPO_NAME, pr_number, IN_TEST_RULES_LABEL):
                            remove_label(session, REPO_OWNER, REPO_NAME, pr_number, IN_TEST_RULES_LABEL)
                        continue

                # Process the file
                target_save_filename = f"{pr_number}_{os.path.basename(file['filename'])}"

                # Get modified content and original ID
                modified_content, original_id = add_id_to_yaml(content, target_save_filename)

                # Add test-rules specific fields
                # Store the original id
                if original_id:
                    modified_content = modified_content.rstrip()
                    modified_content += f'\nog_id: "{original_id}"'

                # Add the PR number as testing_pr
                modified_content = modified_content.rstrip()
                modified_content += f"\ntesting_pr: {pr_number}"

                # Add the commit SHA as testing_sha
                modified_content = modified_content.rstrip()
                modified_content += f"\ntesting_sha: {latest_sha}"

                # Save the file
                save_file(OUTPUT_FOLDER, target_save_filename, modified_content)
                new_files.add(target_save_filename)
                print(f"\tSaved: {target_save_filename}")

                # Apply the in-test-rules label
                if ADD_TEST_RULES_LABEL:
                    if not has_label(session, REPO_OWNER, REPO_NAME, pr_number, IN_TEST_RULES_LABEL):
                        print(f"\tPR #{pr_number} doesn't have the '{IN_TEST_RULES_LABEL}' label. Applying...")
                        apply_label(session, REPO_OWNER, REPO_NAME, pr_number, IN_TEST_RULES_LABEL)

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

    print("Running test-rules sync...")
    session = create_github_session(GITHUB_TOKEN)
    handle_pr_rules(session)
