"""
YAML manipulation utilities for rule files.
"""
import re

from .uuid_utils import generate_deterministic_uuid


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
        modified_content = re.sub(pattern, f'id: "{new_uuid}"', content, flags=re.MULTILINE)
        return modified_content, original_id
    else:
        # If it doesn't exist, add it to the very end of the YAML file
        # Make sure we have a clean end to the file (no trailing whitespace)
        modified_content = content.rstrip()

        # Add a newline and the ID field
        modified_content += f'\nid: "{new_uuid}"'

        return modified_content, original_id


def extract_rule_name(content):
    """
    Extract the rule name from YAML content.

    Args:
        content (str): YAML content

    Returns:
        str: The rule name or empty string if not found
    """
    current_name = ""
    lines = content.split('\n')
    for line in lines:
        if 'name:' in line:
            # replace the quotes and spaces to create a clean filename
            current_name = line.replace('name: ', '', 1).strip()
            break

    return current_name


def prepend_pr_details(rule_name, pr):
    """
    Prepend PR number to rule name.

    Args:
        rule_name (str): Original rule name
        pr (dict): PR object with 'number' key

    Returns:
        str: Modified rule name with PR number prefix
    """
    # maintain the original quoting around the name
    pr_num = pr['number']
    if rule_name.startswith('"') and rule_name.endswith('"'):
        stripped = rule_name.strip('" ')
        new_name = f'"PR# {pr_num} - {stripped}"'
    elif rule_name.startswith("'") and rule_name.endswith("'"):
        stripped = rule_name.strip("' ")
        new_name = f"'PR# {pr_num} - {stripped}'"
    else:
        new_name = f"PR# {pr_num} - {rule_name}"

    return new_name


def rename_rules(content, pr):
    """
    Rename rules in content to include PR number.

    Args:
        content (str): YAML content
        pr (dict): PR object with 'number' key

    Returns:
        str: Modified content with PR number in rule name
    """
    # extract the current name
    current_name = extract_rule_name(content)
    # build out the new name to inject the PR number
    new_name = prepend_pr_details(current_name, pr)

    content = content.replace(current_name, new_name)
    return content


def add_block(yaml_string, block_name, value):
    """
    Add a value to a YAML block (tags or references).

    Args:
        yaml_string (str): The YAML content
        block_name (str): Block name ('tags' or 'references')
        value (str): Value to add to the block

    Returns:
        str: Modified YAML content
    """
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
            # if there isn't a new line found, we've hit the end of the file
            # or if the next line doesn't start with a space (which indicates it's still within the tag section)
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
