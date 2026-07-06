"""
Australia ABN (Australian Business Number) Recognizer

Detects Australian Business Numbers — 11-digit identifiers issued to
businesses. Validated using a weighted checksum algorithm: subtract 1
from the first digit, apply weights [10,1,3,5,7,9,11,13,15,17,19],
sum products, and verify divisible by 89.

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


class AuAbnRecognizer(PatternRecognizer):
    """Recognizer for Australian Business Number (ABN)."""

    PATTERNS = [
        Pattern(
            "au_abn_spaced",
            r"\b\d{2}[\s]\d{3}[\s]\d{3}[\s]\d{3}\b",
            0.6,
        ),
        Pattern(
            "au_abn_compact",
            r"\b\d{11}\b",
            0.2,
        ),
    ]

    CONTEXT = [
        "ABN",
        "australian business number",
        "business number",
        "tax",
        "australia",
        "GST",
    ]

    _WEIGHTS = [10, 1, 3, 5, 7, 9, 11, 13, 15, 17, 19]

    def __init__(self, **kwargs):
        super().__init__(
            supported_entity="AU_ABN",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
            supported_language="en",
            **kwargs,
        )

    def _validate_abn(self, abn_str: str) -> bool:
        """Validate ABN using weighted checksum.

        Steps:
        1. Subtract 1 from the first digit.
        2. Multiply each digit by its weight.
        3. Sum all products.
        4. Valid if sum mod 89 == 0.
        """
        digits = [int(c) for c in abn_str]
        digits[0] -= 1  # Subtract 1 from first digit
        total = sum(d * w for d, w in zip(digits, self._WEIGHTS))
        return total % 89 == 0

    def validate_result(self, pattern_result: RecognizerResult, text: str) -> Optional[RecognizerResult]:
        """Validate the ABN checksum."""
        matched_text = text[pattern_result.start:pattern_result.end]
        digits_only = re.sub(r"[^\d]", "", matched_text)

        if len(digits_only) != 11:
            return self.invalidate_result(pattern_result)

        if not self._validate_abn(digits_only):
            return self.invalidate_result(pattern_result)

        # First two digits cannot both be zero
        if digits_only[:2] == "00":
            return self.invalidate_result(pattern_result)

        pattern_result.score = min(pattern_result.score + 0.3, 1.0)
        return pattern_result

    def invalidate_result(self, pattern_result: RecognizerResult) -> None:
        """Mark result as invalid."""
        pattern_result.score = 0
        return None
