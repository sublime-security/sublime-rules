#!/bin/bash
set -e

# Test script for rule change detection logic
# Tests various scenarios: normal changes, renames, merge commits, metadata-only changes

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEST_DIR="${SCRIPT_DIR}/test-repo"
RESULTS_FILE="${SCRIPT_DIR}/test_results.txt"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

cleanup() {
    rm -rf "${TEST_DIR}"
    rm -f "${RESULTS_FILE}"
}

setup_test_repo() {
    cleanup
    mkdir -p "${TEST_DIR}"
    cd "${TEST_DIR}"

    git init
    git config user.name "Test User"
    git config user.email "test@example.com"

    # Create main branch with initial rules
    mkdir -p detection-rules

    # Rule 1: Will be modified
    cat > detection-rules/rule1.yml <<EOF
name: "Rule 1"
type: "rule"
severity: "medium"
source: |
  type.inbound
  and true
id: "aaaaaaaa-1111-1111-1111-111111111111"
EOF

    # Rule 2: Will be renamed
    cat > detection-rules/rule2.yml <<EOF
name: "Rule 2"
type: "rule"
severity: "high"
source: |
  type.inbound
  and false
id: "bbbbbbbb-2222-2222-2222-222222222222"
EOF

    # Rule 3: Will have only metadata changed
    cat > detection-rules/rule3.yml <<EOF
name: "Rule 3"
type: "rule"
severity: "low"
source: |
  type.inbound
  and sender.email.domain.valid
id: "cccccccc-3333-3333-3333-333333333333"
EOF

    git add .
    git commit -m "Initial commit with rules"
    # Already on main branch after init
}

# Function that mimics the workflow logic
detect_changed_rules() {
    local base_branch="$1"
    local altered_rule_ids=""

    # Get list of changed detection-rules files
    changed_files=$(git diff --name-only --find-renames "${base_branch}...HEAD" -- detection-rules/*.yml 2>/dev/null || echo "")

    for file in $changed_files; do
        if [[ ! -f "$file" ]]; then
            # File was deleted
            rule_id=$(git show "HEAD^:$file" 2>/dev/null | grep "^id:" | cut -d'"' -f2 || echo "unknown")
            if [[ "$rule_id" != "unknown" ]]; then
                echo "DELETED: $file ($rule_id)" >&2
                altered_rule_ids="${rule_id} ${altered_rule_ids}"
            fi
            continue
        fi

        rule_id=$(grep "^id:" "$file" | cut -d'"' -f2)
        new_source=$(grep -A 100 "^source:" "$file" | sed -n '/^source:/,/^[a-z_]*:/p' | grep -v "^[a-z_]*:" || echo "")

        # Find the old file with the same rule ID
        old_file=$(git ls-tree -r --name-only "${base_branch}" -- detection-rules/*.yml 2>/dev/null | while read old_path; do
            old_id=$(git show "${base_branch}:$old_path" 2>/dev/null | grep "^id:" | cut -d'"' -f2 || echo "")
            if [[ "$old_id" == "$rule_id" ]]; then
                echo "$old_path"
                break
            fi
        done)

        if [[ -n "$old_file" ]]; then
            old_source=$(git show "${base_branch}:$old_file" 2>/dev/null | grep -A 100 "^source:" | sed -n '/^source:/,/^[a-z_]*:/p' | grep -v "^[a-z_]*:" || echo "")
        else
            old_source=""
            echo "NEW: $file ($rule_id)" >&2
        fi

        if [[ "$new_source" != "$old_source" ]]; then
            echo "CHANGED: $file ($rule_id)" >&2
            altered_rule_ids="${rule_id} ${altered_rule_ids}"
        else
            echo "METADATA-ONLY: $file ($rule_id)" >&2
        fi
    done

    echo "$altered_rule_ids"
}

run_test() {
    local test_name="$1"
    local expected_count="$2"
    local expected_ids="$3"

    echo -e "\n${YELLOW}=== Test: $test_name ===${NC}"

    result=$(detect_changed_rules "main")
    actual_count=$(echo "$result" | wc -w | tr -d ' ')

    if [[ "$actual_count" == "$expected_count" ]]; then
        echo -e "${GREEN}✓ Pass: Expected $expected_count rules, got $actual_count${NC}"
        echo "PASS: $test_name" >> "${RESULTS_FILE}"
        return 0
    else
        echo -e "${RED}✗ Fail: Expected $expected_count rules, got $actual_count${NC}"
        echo "  Expected IDs: $expected_ids"
        echo "  Actual IDs: $result"
        echo "FAIL: $test_name" >> "${RESULTS_FILE}"
        return 1
    fi
}

# Test 1: Modify rule source
test_modify_source() {
    setup_test_repo
    git checkout -b test-branch

    # Change source of rule1
    sed -i.bak 's/and true/and false/' detection-rules/rule1.yml
    git add detection-rules/rule1.yml
    git commit -m "Change rule1 source"

    run_test "Modify rule source" "1" "aaaaaaaa-1111-1111-1111-111111111111"
}

# Test 2: Rename file (same rule ID)
test_rename_file() {
    setup_test_repo
    git checkout -b test-branch

    # Rename rule2.yml to rule2_renamed.yml
    git mv detection-rules/rule2.yml detection-rules/rule2_renamed.yml
    # Also change its source to make it count
    sed -i.bak 's/and false/and true/' detection-rules/rule2_renamed.yml
    git add detection-rules/rule2_renamed.yml
    git commit -m "Rename and modify rule2"

    run_test "Rename file and change source" "1" "bbbbbbbb-2222-2222-2222-222222222222"
}

# Test 3: Metadata-only change (should NOT trigger)
test_metadata_only() {
    setup_test_repo
    git checkout -b test-branch

    # Change only severity of rule3
    sed -i.bak 's/severity: "low"/severity: "high"/' detection-rules/rule3.yml
    git add detection-rules/rule3.yml
    git commit -m "Change rule3 severity"

    run_test "Metadata-only change" "0" ""
}

# Test 4: Merge commit scenario
test_merge_commit() {
    setup_test_repo

    # Create a branch and make a change
    git checkout -b test-branch
    sed -i.bak 's/and true/and false/' detection-rules/rule1.yml
    git add detection-rules/rule1.yml
    git commit -m "Change rule1"

    # Make a change on main
    git checkout main
    cat > detection-rules/rule4.yml <<EOF
name: "Rule 4"
type: "rule"
severity: "medium"
source: |
  type.inbound
  and recipient.email.domain.valid
id: "dddddddd-4444-4444-4444-444444444444"
EOF
    git add detection-rules/rule4.yml
    git commit -m "Add rule4 on main"

    # Merge main into test-branch
    git checkout test-branch
    git merge main -m "Merge main into test-branch"

    # Should only detect rule1 change, not rule4
    run_test "Merge commit (should detect only PR changes)" "1" "aaaaaaaa-1111-1111-1111-111111111111"
}

# Test 5: New file
test_new_file() {
    setup_test_repo
    git checkout -b test-branch

    # Add a new rule
    cat > detection-rules/rule_new.yml <<EOF
name: "New Rule"
type: "rule"
severity: "high"
source: |
  type.inbound
  and strings.icontains(subject.subject, "urgent")
id: "eeeeeeee-5555-5555-5555-555555555555"
EOF
    git add detection-rules/rule_new.yml
    git commit -m "Add new rule"

    run_test "New file" "1" "eeeeeeee-5555-5555-5555-555555555555"
}

# Run all tests
echo "Starting rule detection tests..."
echo "" > "${RESULTS_FILE}"

test_modify_source
test_rename_file
test_metadata_only
test_merge_commit
test_new_file

# Summary
echo -e "\n${YELLOW}=== Test Summary ===${NC}"
total=$(wc -l < "${RESULTS_FILE}" | tr -d ' ')
passed=$(grep -c "PASS" "${RESULTS_FILE}" 2>/dev/null || echo "0")
failed=$(grep -c "FAIL" "${RESULTS_FILE}" 2>/dev/null || echo "0")

echo "Total: $total"
echo -e "${GREEN}Passed: $passed${NC}"
echo -e "${RED}Failed: $failed${NC}"

cleanup

if [[ "$failed" -gt 0 ]]; then
    exit 1
fi

echo -e "\n${GREEN}All tests passed!${NC}"
