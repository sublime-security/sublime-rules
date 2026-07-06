"""
Hong Kong Identity Card (HKID) Recognizer

Detects Hong Kong Identity Card numbers. Format: X(X)XXXXXX(C)
where X = letter(s), 6 digits, and C = check digit (0-9 or A).
The check digit is computed using a weighted sum modulo 11.

Card view metadata:
  data_categories: [PII]
  data_types: [Government ID]
  regions: [Hong Kong]
  compliance: []
  detection_methods: [Presidio, Content analysis]
"""

import re
from typing import Optional

from presidio_analyzer import Pattern, PatternRecognizer
from presidio_analyzer import RecognizerResult


class HkIdentityCardRecognizer(PatternRecognizer):
    """Recognizer for Hong Kong Identity Card (HKID)."""

    PATTERNS = [
        Pattern(
            "hkid_two_letter",
            r"\b[A-Z]{2}\d{6}\([0-9A]\)\b",
            0.7,
        ),
        Pattern(
            "hkid_one_letter",
            r"\b[A-Z]\d{6}\([0-9A]\)\b",
            0.7,
        ),
        Pattern(
            "hkid_no_parens_two",
            r"\b[A-Z]{2}\d{6}[0-9A]\b",
            0.4,
        ),
        Pattern(
            "hkid_no_parens_one",
            r"\b[A-Z]\d{6}[0-9A]\b",
            0.4,
        ),
    ]

    CONTEXT = [
        "HKID",
        "hong kong",
        "identity card",
        "ID card",
        "身份證",
        "香港身份證",
    ]

    def __init__(self, **kwargs):
        super().__init__(
            supported_entity="HK_IDENTITY_CARD",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
            supported_language="en",
            **kwargs,
        )

    @staticmethod
    def _validate_check_digit(hkid_str: str) -> bool:
        """Validate the HKID check digit.

        For a two-letter prefix: letter1*(9) + letter2*(8) + d1*7 + d2*6 + ... + d6*2 + check*1
        For a one-letter prefix: 36*9 + letter*(8) + d1*7 + d2*6 + ... + d6*2 + check*1
        (A=10, B=11, ..., Z=35; space/missing prefix = 36)
        Sum must be divisible by 11. Check digit A represents 10.
        """
        # Remove parentheses
        cleaned = hkid_str.replace("(", "").replace(")", "").upper()

        # Parse letters and digits
        letters = []
        rest = cleaned
        while rest and rest[0].isalpha():
            letters.append(rest[0])
            rest = rest[1:]

        if len(letters) < 1 or len(letters) > 2:
            return False

        digits_part = rest[:-1]
        check_char = rest[-1]

        if len(digits_part) != 6 or not digits_part.isdigit():
            return False

        # Convert check character
        check_val = 10 if check_char == "A" else int(check_char)

        # Build value list
        values = []
        if len(letters) == 1:
            values.append(36)  # space padding
            values.append(ord(letters[0]) - ord("A") + 10)
        else:
            values.append(ord(letters[0]) - ord("A") + 10)
            values.append(ord(letters[1]) - ord("A") + 10)

        for d in digits_part:
            values.append(int(d))
        values.append(check_val)

        # Weights: 9, 8, 7, 6, 5, 4, 3, 2, 1
        weights = list(range(9, 0, -1))
        total = sum(v * w for v, w in zip(values, weights))

        return total % 11 == 0

    def validate_result(self, pattern_result: RecognizerResult, text: str) -> Optional[RecognizerResult]:
        """Validate the HKID check digit."""
        matched_text = text[pattern_result.start:pattern_result.end]

        if not self._validate_check_digit(matched_text):
            return self.invalidate_result(pattern_result)

        pattern_result.score = min(pattern_result.score + 0.25, 1.0)
        return pattern_result

    def invalidate_result(self, pattern_result: RecognizerResult) -> None:
        """Mark result as invalid."""
        pattern_result.score = 0
        return None
