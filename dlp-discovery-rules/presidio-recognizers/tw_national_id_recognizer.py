"""
Taiwan National ID Recognizer

Detects Taiwan National Identification Card numbers (中華民國國民身分證).
Format: 1 letter + 9 digits. The letter encodes the issuing municipality
and is converted to a two-digit number. A check digit algorithm validates
the entire number.

Card view metadata:
  data_categories: [PII]
  data_types: [Government ID]
  regions: [Taiwan]
  compliance: []
  detection_methods: [Presidio, Content analysis]
"""

import re
from typing import Optional

from presidio_analyzer import Pattern, PatternRecognizer
from presidio_analyzer import RecognizerResult


class TwNationalIdRecognizer(PatternRecognizer):
    """Recognizer for Taiwan National Identification Card Number."""

    PATTERNS = [
        Pattern(
            "tw_national_id",
            r"\b[A-Z][12]\d{8}\b",
            0.5,
        ),
    ]

    CONTEXT = [
        "taiwan",
        "national ID",
        "身分證",
        "身分證字號",
        "identity card",
        "ID number",
        "national identification",
    ]

    # Letter-to-number mapping for Taiwan ID first character
    # Each letter maps to a two-digit number; the first digit contributes
    # to the weighted sum with weight 1, the second with weight 9.
    _LETTER_MAP = {
        "A": 10, "B": 11, "C": 12, "D": 13, "E": 14, "F": 15,
        "G": 16, "H": 17, "I": 34, "J": 18, "K": 19, "L": 20,
        "M": 21, "N": 22, "O": 35, "P": 23, "Q": 24, "R": 25,
        "S": 26, "T": 27, "U": 28, "V": 29, "W": 32, "X": 30,
        "Y": 31, "Z": 33,
    }

    def __init__(self, **kwargs):
        super().__init__(
            supported_entity="TW_NATIONAL_ID",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
            supported_language="en",
            **kwargs,
        )

    def _validate_check_digit(self, id_str: str) -> bool:
        """Validate the Taiwan National ID check digit.

        Algorithm:
        1. Convert the letter to its two-digit numeric value.
        2. Multiply the first digit of the letter value by 1, the second by 9.
        3. Multiply the 8 middle digits by weights [8, 7, 6, 5, 4, 3, 2, 1].
        4. Sum all products plus the check digit (last digit).
        5. Valid if sum mod 10 == 0.
        """
        letter = id_str[0].upper()
        if letter not in self._LETTER_MAP:
            return False

        letter_val = self._LETTER_MAP[letter]
        d1 = letter_val // 10
        d2 = letter_val % 10

        digits = [int(c) for c in id_str[1:]]
        weights = [8, 7, 6, 5, 4, 3, 2, 1]

        total = d1 * 1 + d2 * 9
        total += sum(d * w for d, w in zip(digits[:8], weights))
        total += digits[8]  # check digit

        return total % 10 == 0

    def validate_result(self, pattern_result: RecognizerResult, text: str) -> Optional[RecognizerResult]:
        """Validate the Taiwan National ID check digit."""
        matched_text = text[pattern_result.start:pattern_result.end]

        if not self._validate_check_digit(matched_text):
            return self.invalidate_result(pattern_result)

        pattern_result.score = min(pattern_result.score + 0.35, 1.0)
        return pattern_result

    def invalidate_result(self, pattern_result: RecognizerResult) -> None:
        """Mark result as invalid."""
        pattern_result.score = 0
        return None
