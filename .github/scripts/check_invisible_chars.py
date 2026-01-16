#!/usr/bin/env python3
"""
Detects non-escaped invisible/control characters in rule files.

These characters should be escaped using hex notation:
  - \\x{200F} in regex functions (regex.contains, regex.icontains, etc.)
  - \\u{200F} in string functions (strings.contains, strings.icontains, etc.)

Literal invisible characters are invisible in most editors and can cause confusion.
"""
import os
import re
import sys

# Directories to check for rule files
RULE_DIRS = [
    'detection-rules',
    'discovery-rules',
    'dlp-discovery-rules',
    'insights',
]

# Invisible/control characters that should be escaped
# Format: (unicode codepoint, name)
# Note: We intentionally exclude normal whitespace used in YAML:
#   - 0x0009 (Tab), 0x000A (Line Feed), 0x000D (Carriage Return), 0x0020 (Space)
INVISIBLE_CHARS = [
    # Control characters (excluding normal whitespace)
    (0x000B, 'Line Tabulation'),
    (0x000C, 'Form Feed'),
    # Special spaces
    (0x00A0, 'No-Break Space'),
    (0x00AD, 'Soft Hyphen'),
    (0x034F, 'Combining Grapheme Joiner'),
    (0x061C, 'Arabic Letter Mark'),
    (0x115F, 'Hangul Choseong Filler'),
    (0x1160, 'Hangul Jungseong Filler'),
    (0x1680, 'Ogham Space Mark'),
    (0x17B4, 'Khmer Vowel Inherent Aq'),
    (0x17B5, 'Khmer Vowel Inherent Aa'),
    (0x180E, 'Mongolian Vowel Separator'),
    # Variable-width spaces
    (0x2000, 'En Quad'),
    (0x2001, 'Em Quad'),
    (0x2002, 'En Space'),
    (0x2003, 'Em Space'),
    (0x2004, 'Three-Per-Em Space'),
    (0x2005, 'Four-Per-Em Space'),
    (0x2006, 'Six-Per-Em Space'),
    (0x2007, 'Figure Space'),
    (0x2008, 'Punctuation Space'),
    (0x2009, 'Thin Space'),
    (0x200A, 'Hair Space'),
    # Zero-width characters
    (0x200B, 'Zero Width Space'),
    (0x200C, 'Zero Width Non-Joiner'),
    (0x200D, 'Zero Width Joiner'),
    # Directional formatting
    (0x200E, 'Left-to-Right Mark'),
    (0x200F, 'Right-to-Left Mark'),
    (0x202A, 'Left-to-Right Embedding'),
    (0x202B, 'Right-to-Left Embedding'),
    (0x202C, 'Pop Directional Formatting'),
    (0x202D, 'Left-to-Right Override'),
    (0x202E, 'Right-to-Left Override'),
    (0x202F, 'Narrow No-Break Space'),
    # Mathematical spaces and operators
    (0x205F, 'Medium Mathematical Space'),
    (0x2060, 'Word Joiner'),
    (0x2061, 'Function Application'),
    (0x2062, 'Invisible Times'),
    (0x2063, 'Invisible Separator'),
    (0x2064, 'Invisible Plus'),
    (0x2065, 'Invisible Operator (Undefined)'),
    # Directional isolates
    (0x2066, 'Left-to-Right Isolate'),
    (0x2067, 'Right-to-Left Isolate'),
    (0x2068, 'First Strong Isolate'),
    (0x2069, 'Pop Directional Isolate'),
    # Deprecated format characters
    (0x206A, 'Inhibit Symmetric Swapping'),
    (0x206B, 'Activate Symmetric Swapping'),
    (0x206C, 'Inhibit Arabic Form Shaping'),
    (0x206D, 'Activate Arabic Form Shaping'),
    (0x206E, 'National Digit Shapes'),
    (0x206F, 'Nominal Digit Shapes'),
    # Braille blank
    (0x2800, 'Braille Pattern Blank'),
    # East Asian spaces
    (0x3000, 'Ideographic Space'),
    (0x3164, 'Hangul Filler'),
    # Variation selectors
    (0xFE00, 'Variation Selector-1'),
    (0xFE01, 'Variation Selector-2'),
    (0xFE02, 'Variation Selector-3'),
    (0xFE03, 'Variation Selector-4'),
    (0xFE04, 'Variation Selector-5'),
    (0xFE05, 'Variation Selector-6'),
    (0xFE06, 'Variation Selector-7'),
    (0xFE07, 'Variation Selector-8'),
    (0xFE08, 'Variation Selector-9'),
    (0xFE09, 'Variation Selector-10'),
    (0xFE0A, 'Variation Selector-11'),
    (0xFE0B, 'Variation Selector-12'),
    (0xFE0C, 'Variation Selector-13'),
    (0xFE0D, 'Variation Selector-14'),
    (0xFE0E, 'Variation Selector-15'),
    (0xFE0F, 'Variation Selector-16'),
    # Byte order mark / zero-width no-break space
    (0xFEFF, 'Zero Width No-Break Space (BOM)'),
    # Halfwidth Hangul filler
    (0xFFA0, 'Halfwidth Hangul Filler'),
    # Specials
    (0xFFFC, 'Object Replacement Character'),
    (0xFFF9, 'Interlinear Annotation Anchor'),
    (0xFFFA, 'Interlinear Annotation Separator'),
    (0xFFFB, 'Interlinear Annotation Terminator'),
    # Musical symbols (non-printing)
    (0x1D159, 'Musical Symbol Null Notehead'),
    (0x1D173, 'Musical Symbol Begin Beam'),
    (0x1D174, 'Musical Symbol End Beam'),
    (0x1D175, 'Musical Symbol Begin Tie'),
    (0x1D176, 'Musical Symbol End Tie'),
    (0x1D177, 'Musical Symbol Begin Slur'),
    (0x1D178, 'Musical Symbol End Slur'),
    (0x1D179, 'Musical Symbol Begin Phrase'),
    (0x1D17A, 'Musical Symbol End Phrase'),
    # Tag characters
    (0xE0020, 'Tag Space'),
]

# Build a regex pattern to match any invisible character
INVISIBLE_PATTERN = re.compile(
    '[' + ''.join(chr(cp) for cp, _ in INVISIBLE_CHARS) + ']'
)

# Build a lookup dict for character info: char -> (name, codepoint)
CHAR_INFO = {chr(cp): (name, cp) for cp, name in INVISIBLE_CHARS}


def find_invisible_chars_in_file(filepath: str) -> list[tuple[int, int, str, int]]:
    """
    Find invisible characters in a file.

    Returns a list of tuples: (line_number, column_number, char_name, codepoint)
    """
    issues = []

    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, start=1):
                for match in INVISIBLE_PATTERN.finditer(line):
                    char = match.group()
                    name, codepoint = CHAR_INFO[char]
                    # Column is 1-indexed
                    col_num = match.start() + 1
                    issues.append((line_num, col_num, name, codepoint))
    except UnicodeDecodeError as e:
        print(f"Warning: Could not read {filepath} as UTF-8: {e}", file=sys.stderr)

    return issues


def check_all_rules() -> int:
    """
    Check all rule files for invisible characters.

    Returns the number of files with issues.
    """
    files_with_issues = 0
    total_issues = 0

    for directory in RULE_DIRS:
        if not os.path.exists(directory):
            continue

        for root, dirs, files in os.walk(directory):
            for file in files:
                if file.endswith('.yml'):
                    filepath = os.path.join(root, file)
                    issues = find_invisible_chars_in_file(filepath)

                    if issues:
                        files_with_issues += 1
                        total_issues += len(issues)
                        for line_num, col_num, name, codepoint in issues:
                            hex_code = f"{codepoint:04X}"
                            # GitHub Actions annotation format for inline PR comments
                            # https://docs.github.com/en/actions/using-workflows/workflow-commands-for-github-actions#setting-an-error-message
                            message = f"Found '{name}' (U+{hex_code}). Use \\x{{{hex_code}}} in regex, \\u{{{hex_code}}} in strings"
                            print(f"::error file={filepath},line={line_num},col={col_num},title=Invisible Character::{message}")

    if files_with_issues > 0:
        print(f"\n❌ Found {total_issues} invisible character(s) in {files_with_issues} file(s)")
        print("\nInvisible characters should be escaped using hex notation:")
        print("  - \\x{200F} in regex functions (regex.contains, regex.icontains, etc.)")
        print("  - \\u{200F} in string functions (strings.contains, strings.icontains, etc.)")
        return 1
    else:
        print("✓ No invisible characters found")
        return 0


if __name__ == '__main__':
    sys.exit(check_all_rules())
