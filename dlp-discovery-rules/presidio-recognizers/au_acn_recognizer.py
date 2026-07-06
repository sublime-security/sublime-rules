"""
Australia ACN (Australian Company Number) Recognizer

Detects Australian Company Numbers — 9-digit identifiers for companies.
Validated using a weighted checksum modulo 10: multiply digits by weights
[8,7,6,5,4,3,2,1], sum products, compute (10 - (sum mod 10)) mod 10,
and compare to the last digit.

Card view metadata:
  data_categories: [Financial]
  data_types: [Tax ID]
  regions: [Australia]
  compliance: []
  detection_methods: [Presidio, Content analysis]
"""

import re
from typing import Optional

from presidio_analyzer import Pattern, PatternRecognizer
from presidio_analyzer import RecognizerResult


class AuAcnRecognizer(PatternRecognizer):
    """Recognizer for Australian Company Number (ACN)."""

    PATTERNS = [
        Pattern(
            "au_acn_spaced",
            r"\b\d{3}[\s]\d{3}[\s]\d{3}\b",
            0.4,
        ),
        Pattern(
            "au_acn_compact",
            r"\b\d{9}\b",
            0.1,
        ),
    ]

    CONTEXT = [
        "ACN",
        "australian company number",
        "company number",
        "ASIC",
        "australia",
        "ABN",
    ]

    _WEIGHTS = [8, 7, 6, 5, 4, 3, 2, 1]

    def __init__(self, **kwargs):
        super().__init__(
            supported_entity="AU_ACN",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
            supported_language="en",
            **kwargs,
        )

    def _validate_acn(self, acn_str: str) -> bool:
        """Validate ACN using weighted checksum mod 10.

        Steps:
        1. Multiply first 8 digits by weights [8,7,6,5,4,3,2,1].
        2. Sum all products.
        3. check_digit = (10 - (sum mod 10)) mod 10.
        4. Valid if check_digit == 9th digit.
        """
        digits = [int(c) for c in acn_str]
        total = sum(d * w for d, w in zip(digits[:8], self._WEIGHTS))
        check_digit = (10 - (total % 10)) % 10
        return check_digit == digits[8]

    def validate_result(self, pattern_result: RecognizerResult, text: str) -> Optional[RecognizerResult]:
        """Validate the ACN checksum."""
        matched_text = text[pattern_result.start:pattern_result.end]
        digits_only = re.sub(r"[^\d]", "", matched_text)

        if len(digits_only) != 9:
            return self.invalidate_result(pattern_result)

        if not self._validate_acn(digits_only):
            return self.invalidate_result(pattern_result)

        pattern_result.score = min(pattern_result.score + 0.35, 1.0)
        return pattern_result

    def invalidate_result(self, pattern_result: RecognizerResult) -> None:
        """Mark result as invalid."""
        pattern_result.score = 0
        return None
