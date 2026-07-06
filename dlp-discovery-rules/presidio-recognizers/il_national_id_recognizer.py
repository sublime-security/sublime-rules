"""
Israel National ID (Teudat Zehut) Recognizer

Detects Israeli National ID numbers — 9-digit identifiers validated
using a Luhn-variant algorithm. Each digit is multiplied alternately
by 1 and 2 (from the right). If the product exceeds 9, the digits of
the product are summed. The total must be divisible by 10.

Card view metadata:
  data_categories: [PII]
  data_types: [Government ID]
  regions: [Israel]
  compliance: []
  detection_methods: [Presidio, Content analysis]
"""

import re
from typing import Optional

from presidio_analyzer import Pattern, PatternRecognizer
from presidio_analyzer import RecognizerResult


class IlNationalIdRecognizer(PatternRecognizer):
    """Recognizer for Israel National ID (Teudat Zehut)."""

    PATTERNS = [
        Pattern(
            "il_national_id",
            r"\b\d{9}\b",
            0.2,
        ),
        Pattern(
            "il_national_id_hyphenated",
            r"\b\d{3}-\d{3}-\d{3}\b",
            0.3,
        ),
    ]

    CONTEXT = [
        "teudat zehut",
        "national ID",
        "identity number",
        "ID number",
        "israel",
        "israeli",
    ]

    def __init__(self, **kwargs):
        super().__init__(
            supported_entity="IL_NATIONAL_ID",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
            supported_language="en",
            **kwargs,
        )

    @staticmethod
    def _luhn_variant_check(digits_str: str) -> bool:
        """Validate using the Israeli ID Luhn-variant algorithm.

        For each digit (left to right), multiply alternately by 1 and 2.
        If product > 9, subtract 9 (equivalent to summing the two digits).
        Sum all results. Valid if sum mod 10 == 0.
        """
        total = 0
        for i, ch in enumerate(digits_str):
            digit = int(ch)
            if i % 2 == 1:
                digit *= 2
                if digit > 9:
                    digit -= 9
            total += digit
        return total % 10 == 0

    def validate_result(self, pattern_result: RecognizerResult, text: str) -> Optional[RecognizerResult]:
        """Validate the Israeli National ID check digit."""
        matched_text = text[pattern_result.start:pattern_result.end]
        digits_only = re.sub(r"[^\d]", "", matched_text)

        if len(digits_only) != 9:
            return self.invalidate_result(pattern_result)

        # Pad to 9 digits (IDs can have leading zeros)
        digits_only = digits_only.zfill(9)

        if not self._luhn_variant_check(digits_only):
            return self.invalidate_result(pattern_result)

        # Reject all-zeros
        if digits_only == "000000000":
            return self.invalidate_result(pattern_result)

        pattern_result.score = min(pattern_result.score + 0.4, 1.0)
        return pattern_result

    def invalidate_result(self, pattern_result: RecognizerResult) -> None:
        """Mark result as invalid."""
        pattern_result.score = 0
        return None
