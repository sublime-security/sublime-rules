"""
Constants and configuration values for sync scripts.
"""

# Label names
IN_TEST_RULES_LABEL = 'in-test-rules'
AUTHOR_MEMBERSHIP_EXCLUSION_LABEL = 'test-rules:excluded:author_membership'
MANUAL_EXCLUSION_LABEL = 'test-rules:excluded:manual'
BULK_PR_LABEL = 'test-rules:excluded:bulk_rules'
LINK_ANALYSIS_EXCLUSION_LABEL = 'test-rules:excluded:link_analysis'
SHARED_SAMPLES_AUTHOR_MEMBERSHIP_EXCLUSION_LABEL = 'shared-samples:excluded:author_membership'
SHARED_SAMPLES_BULK_PR_LABEL = 'shared-samples:excluded:bulk_rules'
HUNTING_REQUIRED_LABEL = 'hunting-required'
DO_NOT_MERGE_LABEL = 'do-not-merge'

# Skip texts configuration: {text: [labels_to_apply]}
# Files containing these texts will be skipped from syncing
SKIP_TEXTS = {
    'ml.link_analysis': [HUNTING_REQUIRED_LABEL, LINK_ANALYSIS_EXCLUSION_LABEL]
}

# Default configuration values
DEFAULT_ORG_NAME = 'sublime-security'
DEFAULT_COMMENT_TRIGGER = '/update-test-rules'
DEFAULT_MAX_RULES_PER_PR = 10
DEFAULT_DELETE_RULES_DELAY_DAYS = 3

# Required check configuration
DEFAULT_REQUIRED_CHECK_NAME = 'Rule Tests and ID Updated'
DEFAULT_REQUIRED_CHECK_CONCLUSION = 'success'

# Tag configuration
DEFAULT_AUTHOR_TAG_PREFIX = 'pr_author_'
DEFAULT_RULE_STATUS_PREFIX = 'rule_status_'
DEFAULT_OPEN_PR_TAG = 'created_from_open_prs'
