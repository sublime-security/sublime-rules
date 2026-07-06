"""
Ireland Personal Public Service (PPS) Number Recognizer

Detects Irish PPS numbers: 7 digits + 1-2 letters (e.g., 1234567A or 1234567AB).
Implements check character validation using modulus 23.

Card view metadata:
  data_categories: [PII]
  data_types: [Government ID]
  regions: [Ireland]
  compliance: [GDPR]
  detection_methods: [Presidio, Content analysis]
"""

from presidio_analyzer import Pattern, PatternRecognizer, RecognizerResult


class IePpsRecognizer(PatternRecognizer):
    """Recognizer for Irish Personal Public Service (PPS) Numbers."""

    PATTERNS = [
        Pattern(
            "ie_pps",
            r"\b\d{7}[A-Z]{1,2}\b",
            0.5,
        ),
    ]

    CONTEXT = [
        "PPS", "personal public service", "ireland", "irish",
        "revenue", "social welfare", "RSI",
    ]

    def __init__(self):
        super().__init__(
            supported_entity="IE_PPS",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
            supported_language="en",
        )

    def validate_result(self, pattern_text: str) -> RecognizerResult | None:
        """Validate Irish PPS check character.

        Old format (8 chars): 7 digits + 1 check letter.
        New format (9 chars): 7 digits + 1 check letter + 1 letter (W/T/X/A).

        Check: multiply digits by weights 8,7,6,5,4,3,2.
        For new format, add (9 * value_of_second_letter).
        Sum mod 23 maps to check letter (A=1, B=2, ..., W=23).
        """
        clean = pattern_text.strip()
        digits_part = clean[:7]
        letters_part = clean[7:]

        if not digits_part.isdigit() or len(digits_part) != 7:
            return None

        digits = [int(c) for c in digits_part]
        weights = [8, 7, 6, 5, 4, 3, 2]
        total = sum(d * w for d, w in zip(digits, weights))

        # New format: second letter contributes
        if len(letters_part) == 2:
            second_letter_val = ord(letters_part[1]) - ord('A') + 1
            total += 9 * second_letter_val

        remainder = total % 23
        expected_letter = chr(ord('A') + remainder - 1) if remainder > 0 else 'W'

        if letters_part[0] != expected_letter:
            return None
        return None

    def invalidate_result(self, pattern_text: str) -> bool:
        """Filter out obvious false positives."""
        clean = pattern_text.strip()
        if len(clean) < 8 or len(clean) > 9:
            return True
        digits = [int(c) for c in clean[:7]]
        if len(set(digits)) == 1:
            return True
        return False
