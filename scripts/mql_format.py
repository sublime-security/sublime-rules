#!/usr/bin/env python3
"""
MQL Formatter - formats MQL rules using Sublime's Language Server

Usage:
    # Format files in place
    ./mql_format.py detection-rules/*.yml

    # Check if files need formatting (exit 1 if changes needed)
    ./mql_format.py --check detection-rules/*.yml
"""

import asyncio
import json
import sys
import re
import argparse
from pathlib import Path

try:
    import websockets
except ImportError:
    print("::error::websockets package required. Install with: pip install websockets")
    sys.exit(1)

try:
    import yaml
except ImportError:
    print("::error::PyYAML package required. Install with: pip install pyyaml")
    sys.exit(1)

WS_URL = "wss://play.sublime.security/v1/ws/language-server"
BATCH_SIZE = 50

# Files to exclude from formatting (e.g., special comment formatting)
EXCLUDE_FILES = {
    "attachment_cve_2023_38831.yml",
}


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
    in_source = False
    source_indent = 2  # default

    i = 0
    while i < len(lines):
        line = lines[i]

        if re.match(r'^source:\s*\|', line):
            in_source = True
            result.append(line)

            # Find the indentation from the next non-empty line
            for j in range(i + 1, len(lines)):
                if lines[j].strip():
                    source_indent = len(lines[j]) - len(lines[j].lstrip())
                    break

            # Insert the new formatted source with proper indentation
            # All lines (including blank) get indented to stay in the YAML block
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


async def process_batch(ws, batch: list[dict], start_idx: int, total: int, check_only: bool) -> tuple[int, int]:
    """Process a batch of files concurrently."""
    changed_count = 0
    unchanged_count = 0

    # Send all didOpen and formatting requests
    pending_requests = {}
    for i, file_data in enumerate(batch):
        idx = start_idx + i
        doc_uri = f"inmemory://model/{idx}"
        request_id = idx + 1

        await ws.send(json.dumps({
            "jsonrpc": "2.0", "method": "textDocument/didOpen",
            "params": {
                "textDocument": {
                    "uri": doc_uri,
                    "languageId": "mql",
                    "version": 1,
                    "text": file_data["source"]
                }
            }
        }))

        await ws.send(json.dumps({
            "jsonrpc": "2.0", "id": request_id, "method": "textDocument/formatting",
            "params": {
                "textDocument": {"uri": doc_uri},
                "options": {"tabSize": 2, "insertSpaces": True}
            }
        }))

        pending_requests[request_id] = {
            "file_data": file_data,
            "idx": idx,
            "doc_uri": doc_uri
        }

    # Collect responses
    while pending_requests:
        msg = json.loads(await ws.recv())

        if "id" not in msg:
            continue

        request_id = msg.get("id")
        if request_id not in pending_requests:
            continue

        req_data = pending_requests.pop(request_id)
        file_data = req_data["file_data"]
        idx = req_data["idx"]
        doc_uri = req_data["doc_uri"]
        path = file_data["path"]
        content = file_data["content"]
        original_source = file_data["source"]
        progress = f"[{idx + 1}/{total}]"

        formatted_source = original_source
        if msg.get("result"):
            formatted_source = msg["result"][0]["newText"]

        await ws.send(json.dumps({
            "jsonrpc": "2.0", "method": "textDocument/didClose",
            "params": {"textDocument": {"uri": doc_uri}}
        }))

        # Normalize for comparison (ignore trailing whitespace)
        def normalize(s):
            return '\n'.join(line.rstrip() for line in s.strip().split('\n'))

        if normalize(formatted_source) != normalize(original_source):
            changed_count += 1
            if check_only:
                print(f"::error file={path}::{progress} {path.name} needs formatting", flush=True)
            else:
                result = replace_source(content, formatted_source)
                path.write_text(result)
                print(f"{progress} {path.name} reformatted", flush=True)
        else:
            unchanged_count += 1
            print(f"{progress} {path.name} unchanged", flush=True)

    return changed_count, unchanged_count


async def process_files(files_data: list[dict], check_only: bool) -> tuple[int, int]:
    """Process files using batched concurrent requests."""
    changed_count = 0
    unchanged_count = 0
    total = len(files_data)

    async with websockets.connect(WS_URL) as ws:
        await ws.send(json.dumps({"demo_mode": False}))
        auth_resp = json.loads(await ws.recv())
        if not auth_resp.get("authenticated"):
            print(f"::error::Authentication failed: {auth_resp}")
            raise Exception(f"Authentication failed: {auth_resp}")

        await ws.send(json.dumps({
            "jsonrpc": "2.0", "id": 0, "method": "initialize",
            "params": {
                "processId": None,
                "clientInfo": {"name": "MQL-Formatter-CI"},
                "capabilities": {},
                "rootUri": None
            }
        }))
        await ws.recv()
        await ws.send(json.dumps({"jsonrpc": "2.0", "method": "initialized", "params": {}}))

        for batch_start in range(0, total, BATCH_SIZE):
            batch = files_data[batch_start:batch_start + BATCH_SIZE]
            batch_changed, batch_unchanged = await process_batch(
                ws, batch, batch_start, total, check_only
            )
            changed_count += batch_changed
            unchanged_count += batch_unchanged

    return changed_count, unchanged_count


def main():
    parser = argparse.ArgumentParser(
        description="Format MQL rules using Sublime's Language Server"
    )
    parser.add_argument("files", nargs="+", help="YAML rule files to format")
    parser.add_argument("--check", action="store_true",
                        help="Check if files are formatted (exit 1 if not)")
    args = parser.parse_args()

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

    print(f"Processing {len(files_data)} files in batches of {BATCH_SIZE}...", flush=True)

    try:
        changed_count, unchanged_count = asyncio.run(process_files(files_data, args.check))
    except Exception as e:
        print(f"::error::Formatting failed: {e}")
        sys.exit(1)

    print(f"\n{'─' * 50}", flush=True)
    if args.check:
        if changed_count > 0:
            print(f"::error::{changed_count} files need formatting, {unchanged_count} files OK")
            sys.exit(1)
        else:
            print(f"✓ All {unchanged_count} files are properly formatted")
    else:
        print(f"✓ {changed_count} files reformatted, {unchanged_count} unchanged")


if __name__ == "__main__":
    main()
