"""
Japan MyNumber Recognizer

Detects Japanese Individual Number (MyNumber / マイナンバー), a 12-digit
national identification number. The last digit is a check digit computed
using a weighted sum modulo 11.

Card view metadata:
  data_categories: [PII]
  data_types: [Government ID]
  regions: [Japan]
  compliance: []
  detection_methods: [Presidio, Content analysis]
"""

import re
from typing import List, Optional

from presidio_analyzer import Pattern, PatternRecognizer
from presidio_analyzer import RecognizerResult


class JpMyNumberRecognizer(PatternRecognizer):
    """Recognizer for Japan MyNumber (Individual Number / マイナンバー)."""

    PATTERNS = [
        Pattern(
            "jp_my_number_spaced",
            r"\b\d{4}[\s\-]\d{4}[\s\-]\d{4}\b",
            0.5,
        ),
        Pattern(
            "jp_my_number_compact",
            r"\b\d{12}\b",
            0.3,
        ),
    ]

    CONTEXT = [
        "mynumber",
        "my number",
        "マイナンバー",
        "個人番号",
        "individual number",
        "japan",
    ]

    def __init__(self, **kwargs):
        super().__init__(
            supported_entity="JP_MY_NUMBER",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
            supported_language="en",
            **kwargs,
        )

    @staticmethod
    def _compute_check_digit(digits: List[int]) -> int:
        """Compute the MyNumber check digit (12th digit) from the first 11 digits.

        Algorithm:
        - Weights for positions 1-11 (from left): Q_n where
          Q_n = n + 1 for n in 1..6 and Q_n = n - 5 for n in 7..11
          Applied in reverse order to the digit positions.
        - Sum = sum of (digit_i * weight_i) for i = 0..10
        - remainder = Sum mod 11
        - If remainder <= 1: check digit = 0
        - Else: check digit = 11 - remainder
        """
        weights = [6, 5, 4, 3, 2, 7, 6, 5, 4, 3, 2]
        total = sum(d * w for d, w in zip(digits, weights))
        remainder = total % 11
        if remainder <= 1:
            return 0
        return 11 - remainder

    def validate_result(self, pattern_result: RecognizerResult, text: str) -> Optional[RecognizerResult]:
        """Validate the MyNumber check digit."""
        matched_text = text[pattern_result.start:pattern_result.end]
        # Extract only digits
        digits_only = re.sub(r"[^\d]", "", matched_text)

        if len(digits_only) != 12:
            return self.invalidate_result(pattern_result)

        digits = [int(d) for d in digits_only]
        expected_check = self._compute_check_digit(digits[:11])

        if digits[11] != expected_check:
            return self.invalidate_result(pattern_result)

        # Valid check digit — boost confidence
        pattern_result.score = min(pattern_result.score + 0.3, 1.0)
        return pattern_result

    def invalidate_result(self, pattern_result: RecognizerResult) -> None:
        """Mark result as invalid."""
        pattern_result.score = 0
        return None
