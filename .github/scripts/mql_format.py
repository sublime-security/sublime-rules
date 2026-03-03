#!/usr/bin/env python3
"""
MQL Formatter - formats MQL rules using Sublime's Format API

Usage:
    # Format files in place
    ./mql_format.py detection-rules/*.yml

    # Check if files need formatting (exit 1 if changes needed)
    ./mql_format.py --check detection-rules/*.yml
"""

import sys
import re
import argparse
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import requests
except ImportError:
    print("::error::requests package required. Install with: pip install requests")
    sys.exit(1)

try:
    import yaml
except ImportError:
    print("::error::PyYAML package required. Install with: pip install pyyaml")
    sys.exit(1)

API_URL = "https://play.sublime.security/v1/rules/format"
MAX_WORKERS = 100

# Files to exclude from formatting (e.g., special comment formatting)
EXCLUDE_FILES = {
    "attachment_cve_2023_38831.yml",
}


def format_source(source: str) -> str:
    """Format MQL source using the Sublime API."""
    resp = requests.post(API_URL, json={
        "source": source,
        "max_line_width": 80,
        "indent": 2,
        "prefer_multi_line_root": True,
    }, timeout=30)

    # Handle 500 errors gracefully - this is a known API bug with empty comment lines
    if resp.status_code == 500:
        error = requests.HTTPError("500 Server Error")
        error.response = resp
        raise error

    resp.raise_for_status()
    return resp.json()["source"]


def extract_source(content: str) -> str | None:
    """Extract source field using PyYAML."""
    try:
        data = yaml.safe_load(content)
        return data.get("source") if data else None
    except yaml.YAMLError:
        return None


def replace_source(content: str, new_source: str) -> str:
    """Replace source block in YAML file, preserving everything else."""
    lines = content.split('\n')
    result = []
    source_indent = 2  # default

    i = 0
    while i < len(lines):
        line = lines[i]

        if re.match(r'^source:\s*\|', line):
            result.append(line)

            # Find the indentation from the next non-empty line
            for j in range(i + 1, len(lines)):
                if lines[j].strip():
                    source_indent = len(lines[j]) - len(lines[j].lstrip())
                    break

            # Insert the new formatted source with proper indentation
            indent = ' ' * source_indent
            for src_line in new_source.split('\n'):
                result.append(indent + src_line)

            # Skip the old source lines
            i += 1
            while i < len(lines):
                if not lines[i].strip():  # blank line
                    i += 1
                elif lines[i][0].isspace():  # indented = still in source
                    i += 1
                else:  # non-indented = next field
                    break
            continue

        result.append(line)
        i += 1

    return '\n'.join(result)


def normalize(s: str) -> str:
    """Normalize source for comparison (ignore trailing whitespace)."""
    return '\n'.join(line.rstrip() for line in s.strip().split('\n'))


def process_file(file_data: dict) -> dict:
    """Process a single file - called in thread pool."""
    path = file_data["path"]
    content = file_data["content"]
    source = file_data["source"]

    try:
        formatted_source = format_source(source)
        changed = normalize(formatted_source) != normalize(source)
        return {
            "path": path,
            "content": content,
            "formatted_source": formatted_source,
            "changed": changed,
            "error": None,
            "is_500": False
        }
    except requests.HTTPError as e:
        # Check if this is a 500 error
        # Note: Response object may be falsy even if it exists, so use hasattr + is not None
        if hasattr(e, 'response') and e.response is not None and hasattr(e.response, 'status_code') and e.response.status_code == 500:
            return {
                "path": path,
                "error": "500 Server Error",
                "is_500": True
            }
        return {
            "path": path,
            "error": str(e),
            "is_500": False
        }
    except requests.RequestException as e:
        return {
            "path": path,
            "error": str(e),
            "is_500": False
        }


def main():
    parser = argparse.ArgumentParser(
        description="Format MQL rules using Sublime's Format API"
    )
    parser.add_argument("files", nargs="+", help="YAML rule files to format")
    parser.add_argument("--check", action="store_true",
                        help="Check if files are formatted (exit 1 if not)")
    args = parser.parse_args()

    # Collect files to process
    files_data = []
    for filepath in args.files:
        path = Path(filepath)
        if not path.exists():
            print(f"::warning file={filepath}::{filepath} does not exist, skipping")
            continue

        if path.name in EXCLUDE_FILES:
            print(f"[skip] {path.name} excluded", flush=True)
            continue

        content = path.read_text()
        source = extract_source(content)
        if not source:
            print(f"::warning file={filepath}::{path.name} has no source field, skipping")
            continue

        files_data.append({
            "path": path,
            "content": content,
            "source": source
        })

    if not files_data:
        print("::error::No valid files to process")
        sys.exit(1)

    total = len(files_data)
    print(f"Processing {total} files with {MAX_WORKERS} workers...", flush=True)

    changed_count = 0
    unchanged_count = 0
    completed = 0

    # Process files in parallel
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(process_file, fd): fd for fd in files_data}

        for future in as_completed(futures):
            result = future.result()
            completed += 1
            progress = f"[{completed}/{total}]"
            path = result["path"]

            if result.get("error"):
                # Handle 500 errors as warnings
                if result.get("is_500"):
                    print(f"::warning file={path}::{progress} {path.name} skipped - API returned 500 error", flush=True)
                    unchanged_count += 1
                    continue
                else:
                    print(f"::error file={path}::{progress} {path.name} formatting failed: {result['error']}")
                    sys.exit(1)

            if result["changed"]:
                changed_count += 1
                if args.check:
                    print(f"::error file={path}::{progress} {path.name} needs formatting", flush=True)
                else:
                    new_content = replace_source(result["content"], result["formatted_source"])
                    path.write_text(new_content)
                    print(f"{progress} {path.name} reformatted", flush=True)
            else:
                unchanged_count += 1
                print(f"{progress} {path.name} unchanged", flush=True)

    print(f"\n{'─' * 50}", flush=True)
    if args.check:
        if changed_count > 0:
            print(f"::error::{changed_count} files need formatting, {unchanged_count} files OK")
            sys.exit(1)
        else:
            print(f"All {unchanged_count} files are properly formatted")
    else:
        print(f"{changed_count} files reformatted, {unchanged_count} unchanged")


if __name__ == "__main__":
    main()
