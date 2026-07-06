"""
New Zealand IRD (Inland Revenue Department) Number Recognizer

Detects New Zealand IRD numbers — 8 or 9 digit tax identification
numbers. The last digit is a check digit computed using a weighted
sum modulo 11. If the first pass yields a remainder of 0, a second
set of weights is applied.

Card view metadata:
  data_categories: [Financial]
  data_types: [Tax ID]
  regions: [New Zealand]
  compliance: []
  detection_methods: [Presidio, Content analysis]
"""

import re
from typing import Optional

from presidio_analyzer import Pattern, PatternRecognizer
from presidio_analyzer import RecognizerResult


class NzIrdRecognizer(PatternRecognizer):
    """Recognizer for New Zealand IRD Number."""

    PATTERNS = [
        Pattern(
            "nz_ird_formatted",
            r"\b\d{2,3}-\d{3}-\d{3}\b",
            0.5,
        ),
        Pattern(
            "nz_ird_compact",
            r"\b\d{8,9}\b",
            0.1,
        ),
    ]

    CONTEXT = [
        "IRD",
        "inland revenue",
        "tax number",
        "GST",
        "new zealand",
        "NZ",
        "tax ID",
    ]

    # Primary weights for 8-digit IRD
    _WEIGHTS_8_PRIMARY = [3, 2, 7, 6, 5, 4, 3]
    _WEIGHTS_8_SECONDARY = [7, 4, 3, 2, 5, 2, 7]
    # Primary weights for 9-digit IRD
    _WEIGHTS_9_PRIMARY = [3, 2, 7, 6, 5, 4, 3, 2]
    _WEIGHTS_9_SECONDARY = [7, 4, 3, 2, 5, 2, 7, 6]

    def __init__(self, **kwargs):
        super().__init__(
            supported_entity="NZ_IRD",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
            supported_language="en",
            **kwargs,
        )

    @staticmethod
    def _check_with_weights(digits: list, weights: list) -> int:
        """Compute check digit using given weights.

        Sum = sum of (digit[i] * weight[i]) for i in range(len(weights)).
        remainder = Sum mod 11.
        If remainder == 0: check digit = 0.
        Else: check digit = 11 - remainder.
        Returns -1 if check digit would be 10 (invalid with these weights).
        """
        total = sum(d * w for d, w in zip(digits, weights))
        remainder = total % 11
        if remainder == 0:
            return 0
        check = 11 - remainder
        if check == 10:
            return -1  # Need to try secondary weights
        return check

    def _validate_ird(self, digits_str: str) -> bool:
        """Validate IRD number check digit."""
        digits = [int(c) for c in digits_str]
        check_digit = digits[-1]
        body = digits[:-1]

        if len(digits) == 8:
            primary = self._WEIGHTS_8_PRIMARY
            secondary = self._WEIGHTS_8_SECONDARY
        elif len(digits) == 9:
            primary = self._WEIGHTS_9_PRIMARY
            secondary = self._WEIGHTS_9_SECONDARY
        else:
            return False

        expected = self._check_with_weights(body, primary)
        if expected == -1:
            expected = self._check_with_weights(body, secondary)
            if expected == -1:
                return False

        return check_digit == expected

    def validate_result(self, pattern_result: RecognizerResult, text: str) -> Optional[RecognizerResult]:
        """Validate the IRD number check digit."""
        matched_text = text[pattern_result.start:pattern_result.end]
        digits_only = re.sub(r"[^\d]", "", matched_text)

        if len(digits_only) not in (8, 9):
            return self.invalidate_result(pattern_result)

        # IRD numbers range: 10,000,000 to 150,000,000
        num_val = int(digits_only)
        if num_val < 10_000_000 or num_val > 150_000_000:
            return self.invalidate_result(pattern_result)

        if not self._validate_ird(digits_only):
            return self.invalidate_result(pattern_result)

        pattern_result.score = min(pattern_result.score + 0.35, 1.0)
        return pattern_result

    def invalidate_result(self, pattern_result: RecognizerResult) -> None:
        """Mark result as invalid."""
        pattern_result.score = 0
        return None
