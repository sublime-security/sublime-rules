"""
Shared library for sync scripts.
"""
from .constants import (
    IN_TEST_RULES_LABEL,
    AUTHOR_MEMBERSHIP_EXCLUSION_LABEL,
    MANUAL_EXCLUSION_LABEL,
    BULK_PR_LABEL,
    LINK_ANALYSIS_EXCLUSION_LABEL,
    HUNTING_REQUIRED_LABEL,
    DO_NOT_MERGE_LABEL,
    SKIP_TEXTS,
    DEFAULT_ORG_NAME,
    DEFAULT_COMMENT_TRIGGER,
    DEFAULT_MAX_RULES_PER_PR,
    DEFAULT_DELETE_RULES_DELAY_DAYS,
    DEFAULT_REQUIRED_CHECK_NAME,
    DEFAULT_REQUIRED_CHECK_CONCLUSION,
    DEFAULT_AUTHOR_TAG_PREFIX,
    DEFAULT_RULE_STATUS_PREFIX,
    DEFAULT_OPEN_PR_TAG,
)

from .github_client import create_github_session

from .graphql_client import create_graphql_session, fetch_all_prs

from .pr_data import PRData

from .labels import apply_label, remove_label

from .yaml_utils import (
    check_skip_texts,
    add_id_to_yaml,
    extract_rule_name,
    prepend_pr_details,
    rename_rules,
    add_block,
)

from .uuid_utils import generate_deterministic_uuid

from .file_utils import (
    get_file_contents,
    save_file,
    pr_has_synced_files,
    clean_output_folder,
    count_yaml_rules_in_pr,
)

from .pr_comments import (
    add_pr_comment,
    has_existing_comment,
    generate_exclusion_comment,
    post_exclusion_comment_if_needed,
    COMMENT_MARKER,
)

__all__ = [
    # Constants
    'IN_TEST_RULES_LABEL',
    'AUTHOR_MEMBERSHIP_EXCLUSION_LABEL',
    'MANUAL_EXCLUSION_LABEL',
    'BULK_PR_LABEL',
    'LINK_ANALYSIS_EXCLUSION_LABEL',
    'HUNTING_REQUIRED_LABEL',
    'DO_NOT_MERGE_LABEL',
    'SKIP_TEXTS',
    'DEFAULT_ORG_NAME',
    'DEFAULT_COMMENT_TRIGGER',
    'DEFAULT_MAX_RULES_PER_PR',
    'DEFAULT_DELETE_RULES_DELAY_DAYS',
    'DEFAULT_REQUIRED_CHECK_NAME',
    'DEFAULT_REQUIRED_CHECK_CONCLUSION',
    'DEFAULT_AUTHOR_TAG_PREFIX',
    'DEFAULT_RULE_STATUS_PREFIX',
    'DEFAULT_OPEN_PR_TAG',
    # GitHub client (REST)
    'create_github_session',
    # GraphQL client
    'create_graphql_session',
    'fetch_all_prs',
    # PR data model
    'PRData',
    # Labels (write operations only)
    'apply_label',
    'remove_label',
    # YAML utils
    'check_skip_texts',
    'add_id_to_yaml',
    'extract_rule_name',
    'prepend_pr_details',
    'rename_rules',
    'add_block',
    # UUID utils
    'generate_deterministic_uuid',
    # File utils
    'get_file_contents',
    'save_file',
    'pr_has_synced_files',
    'clean_output_folder',
    'count_yaml_rules_in_pr',
    # PR comments
    'add_pr_comment',
    'has_existing_comment',
    'generate_exclusion_comment',
    'post_exclusion_comment_if_needed',
    'COMMENT_MARKER',
]
