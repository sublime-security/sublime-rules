#!/usr/bin/env python3
"""
Detects root_domain comparisons against subdomain values in rule files.

Since the Sublime platform uses the Public Suffix List (PSL) to determine
root domains, comparing .root_domain against a value that contains a subdomain
(e.g., "privaterelay.appleid.com") will silently fail -- the actual root_domain
for that value would be "appleid.com".

This script catches these mistakes before they reach production.
"""
import os
import re
import sys

import tldextract
import yaml

# Directories to check for rule files
RULE_DIRS = [
    'detection-rules',
    'discovery-rules',
    'dlp-discovery-rules',
    'insights',
]

# Initialize tldextract with bundled PSL snapshot (no network calls)
_extract = tldextract.TLDExtract(suffix_list_urls=None)


def find_source_line_offset(filepath):
    """Find the line number where `source: |` appears in a YAML file.

    Returns the 1-based line number of the first line of MQL content
    (i.e., the line after `source: |`).
    """
    with open(filepath, 'r', encoding='utf-8') as f:
        for i, line in enumerate(f, start=1):
            if re.match(r'^source:\s*[|>]', line):
                return i + 1
    return 1


def strip_mql_comments(line):
    """Remove // line comments from an MQL line, respecting quoted strings."""
    in_string = False
    quote_char = None
    i = 0
    while i < len(line):
        ch = line[i]
        if in_string:
            if ch == '\\':
                i += 2
                continue
            if ch == quote_char:
                in_string = False
        else:
            if ch in ('"', "'"):
                in_string = True
                quote_char = ch
            elif ch == '/' and i + 1 < len(line) and line[i + 1] == '/':
                return line[:i]
        i += 1
    return line


def extract_string_literals(text):
    """Extract all double-quoted string literals from MQL text.

    Returns a list of (value, start_pos) tuples where start_pos is the
    position of the opening quote in the text.
    """
    literals = []
    i = 0
    while i < len(text):
        if text[i] == '"':
            start = i
            i += 1
            value = []
            while i < len(text) and text[i] != '"':
                if text[i] == '\\':
                    i += 1
                    if i < len(text):
                        value.append(text[i])
                else:
                    value.append(text[i])
                i += 1
            if i < len(text):
                literals.append((''.join(value), start))
            i += 1
        elif text[i] == "'":
            # Skip single-quoted strings
            i += 1
            while i < len(text) and text[i] != "'":
                if text[i] == '\\':
                    i += 1
                i += 1
            i += 1
        else:
            i += 1
    return literals


def pos_to_line(text, pos):
    """Convert a character position to a 1-based line number within the text."""
    return text[:pos].count('\n') + 1


def find_root_domain_violations(source):
    """Find root_domain comparisons against subdomain values in MQL source.

    Returns a list of (mql_line_number, domain_literal, suggested_fix) tuples.
    """
    violations = []
    lines = source.split('\n')

    # First, strip comments from each line and rejoin
    stripped_lines = [strip_mql_comments(line) for line in lines]
    stripped_source = '\n'.join(stripped_lines)

    # Pattern 1: .root_domain == "domain" or .root_domain != "domain"
    eq_pattern = re.compile(
        r'\.root_domain\s*(?:==|!=)\s*"([^"]*)"'
    )
    for m in eq_pattern.finditer(stripped_source):
        domain = m.group(1)
        if domain.startswith('$'):
            continue
        violation = check_domain(domain)
        if violation:
            line_num = pos_to_line(stripped_source, m.start())
            violations.append((line_num, domain, violation))

    # Pattern 2: .root_domain in/in~/not in/not in~ (...) with string literals
    in_pattern = re.compile(
        r'\.root_domain\s+(?:not\s+)?in~?\s*\('
    )
    for m in in_pattern.finditer(stripped_source):
        # Find the matching closing paren
        paren_start = m.end() - 1
        depth = 1
        pos = paren_start + 1
        while pos < len(stripped_source) and depth > 0:
            if stripped_source[pos] == '(':
                depth += 1
            elif stripped_source[pos] == ')':
                depth -= 1
            pos += 1
        paren_content = stripped_source[paren_start:pos]

        # Extract string literals from the parenthesized list
        for literal_val, literal_start in extract_string_literals(paren_content):
            if literal_val.startswith('$'):
                continue
            violation = check_domain(literal_val)
            if violation:
                abs_pos = paren_start + literal_start
                line_num = pos_to_line(stripped_source, abs_pos)
                violations.append((line_num, literal_val, violation))

    return violations


def check_domain(domain):
    """Check if a domain literal has a subdomain component.

    Returns the suggested root_domain if it's a violation, or None if OK.
    """
    result = _extract(domain)
    if result.subdomain:
        # It has a subdomain -- this is a violation
        root = f"{result.domain}.{result.suffix}"
        return root
    return None


def check_all_rules():
    """Check all rule files for root_domain subdomain violations.

    Returns exit code: 1 if violations found, 0 if clean.
    """
    files_with_issues = 0
    total_issues = 0

    for directory in RULE_DIRS:
        if not os.path.exists(directory):
            continue

        for root, dirs, files in os.walk(directory):
            for filename in sorted(files):
                if not filename.endswith('.yml'):
                    continue

                filepath = os.path.join(root, filename)

                try:
                    with open(filepath, 'r', encoding='utf-8') as f:
                        data = yaml.safe_load(f)
                except Exception:
                    continue

                if not data or 'source' not in data:
                    continue

                source = data['source']
                if not isinstance(source, str):
                    continue

                violations = find_root_domain_violations(source)
                if not violations:
                    continue

                source_offset = find_source_line_offset(filepath)
                files_with_issues += 1
                total_issues += len(violations)

                for mql_line, domain, suggested in violations:
                    file_line = source_offset + mql_line - 1
                    message = (
                        f'root_domain compared against subdomain value "{domain}". '
                        f'root_domain resolves to "{suggested}". '
                        f'Use "{suggested}" or compare against .domain.domain instead.'
                    )
                    print(
                        f"::error file={filepath},line={file_line},"
                        f"title=root_domain subdomain mismatch::{message}"
                    )

    if total_issues > 0:
        print(
            f"\n\u274c Found {total_issues} root_domain subdomain "
            f"mismatch(es) in {files_with_issues} file(s)"
        )
        print(
            "\nroot_domain uses the Public Suffix List to extract the "
            "registrable domain."
        )
        print(
            'For example, root_domain of "privaterelay.appleid.com" '
            'is "appleid.com".'
        )
        print(
            "Either fix the literal or use .domain.domain for exact "
            "hostname matching."
        )
        return 1
    else:
        print("\u2713 No root_domain subdomain mismatches found")
        return 0


if __name__ == '__main__':
    sys.exit(check_all_rules())
