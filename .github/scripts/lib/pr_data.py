"""
PR data model for GraphQL-fetched pull request data.

This module provides a dataclass that encapsulates all PR data fetched via
GraphQL, with helper methods for common checks that previously required
individual API calls.
"""
from dataclasses import dataclass
from typing import Dict, List, Optional, Set

# Author associations that indicate org membership
ORG_MEMBER_ASSOCIATIONS = frozenset({'MEMBER', 'COLLABORATOR', 'OWNER'})


@dataclass
class PRData:
    """
    Represents a pull request with all related data.

    All data is fetched in bulk via GraphQL, so checks against this data
    are performed in-memory without additional API calls.
    """
    number: int
    title: str
    is_draft: bool
    state: str  # OPEN, CLOSED, MERGED
    merged_at: Optional[str]
    closed_at: Optional[str]
    url: str
    base_ref: str
    head_sha: str
    author_login: Optional[str]
    author_association: str  # MEMBER, COLLABORATOR, OWNER, CONTRIBUTOR, etc.
    labels: Set[str]
    files: List[Dict]  # [{filename, status}]
    comments: List[Dict]  # [{body, author_login, author_association}]
    check_runs: List[Dict]  # [{name, conclusion, status}]

    def has_label(self, name: str) -> bool:
        """
        Check if PR has a specific label.

        Args:
            name: Label name to check for.

        Returns:
            True if PR has the label.
        """
        return name in self.labels

    def is_author_org_member(self) -> bool:
        """
        Check if PR author is an org member based on authorAssociation.

        GitHub's authorAssociation field indicates the relationship:
        - MEMBER: Direct org member
        - COLLABORATOR: Repository collaborator
        - OWNER: Repository owner

        Returns:
            True if author is an org member.
        """
        return self.author_association in ORG_MEMBER_ASSOCIATIONS

    def has_trigger_comment(self, trigger: str) -> bool:
        """
        Check if PR has a comment with trigger text from an org member.

        Args:
            trigger: Trigger text to look for in comments.

        Returns:
            True if a matching comment from an org member is found.
        """
        for comment in self.comments:
            if trigger in comment.get('body', ''):
                if comment.get('author_association') in ORG_MEMBER_ASSOCIATIONS:
                    return True
        return False

    def has_required_check(self, name: str, conclusion: str) -> bool:
        """
        Check if PR has a completed check with the required conclusion.

        Args:
            name: Check name to look for (case-insensitive substring match).
            conclusion: Required conclusion (e.g., 'success').

        Returns:
            True if matching check with correct conclusion is found.
        """
        name_lower = name.lower()
        conclusion_upper = conclusion.upper()

        for check in self.check_runs:
            check_name = check.get('name', '')
            check_conclusion = check.get('conclusion')
            check_status = check.get('status')

            if name_lower in check_name.lower():
                # Check must be completed
                if check_status != 'COMPLETED':
                    return False
                # Check conclusion (GraphQL returns uppercase)
                return check_conclusion == conclusion_upper

        return False

    def get_yaml_rule_files(self) -> List[Dict]:
        """
        Get list of YAML rule files that are added/modified in detection-rules/.

        Returns:
            List of file dicts with filename and status.
        """
        return [
            f for f in self.files
            if (f['status'] in ('added', 'modified', 'changed') and
                f['filename'].startswith('detection-rules/') and
                f['filename'].endswith('.yml'))
        ]

    def count_yaml_rules(self) -> int:
        """
        Count number of YAML rule files in the PR.

        Returns:
            Number of YAML files in detection-rules directory.
        """
        return len(self.get_yaml_rule_files())
