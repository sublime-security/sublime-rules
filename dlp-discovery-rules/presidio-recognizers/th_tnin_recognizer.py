"""
Thailand TNIN (Thai National Identification Number) Recognizer

Detects Thai National Identification Numbers — 13-digit numbers with
format X-XXXX-XXXXX-XX-X. The last digit is a check digit computed
as: (11 - (sum of (digit_i * (14-i)) for i=1..12) mod 11) mod 10.

Card view metadata:
  data_categories: [PII]
  data_types: [Government ID]
  regions: [Thailand]
  compliance: []
  detection_methods: [Presidio, Content analysis]
"""

import re
from typing import Optional

from presidio_analyzer import Pattern, PatternRecognizer
from presidio_analyzer import RecognizerResult


class ThTninRecognizer(PatternRecognizer):
    """Recognizer for Thailand National Identification Number (TNIN)."""

    PATTERNS = [
        Pattern(
            "th_tnin_formatted",
            r"\b\d-\d{4}-\d{5}-\d{2}-\d\b",
            0.7,
        ),
        Pattern(
            "th_tnin_compact",
            r"\b[1-8]\d{12}\b",
            0.3,
        ),
    ]

    CONTEXT = [
        "thai ID",
        "national ID",
        "identification number",
        "thailand",
        "citizen ID",
        "TNIN",
        "บัตรประชาชน",
        "เลขบัตรประชาชน",
    ]

    def __init__(self, **kwargs):
        super().__init__(
            supported_entity="TH_TNIN",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
            supported_language="en",
            **kwargs,
        )

    @staticmethod
    def _validate_check_digit(digits_str: str) -> bool:
        """Validate the Thai NIN check digit.

        Sum = sum of (digit[i] * (13 - i)) for i = 0..11
        check = (11 - (Sum mod 11)) mod 10
        """
        digits = [int(c) for c in digits_str]
        total = sum(d * (13 - i) for i, d in enumerate(digits[:12]))
        expected = (11 - (total % 11)) % 10
        return digits[12] == expected

    def validate_result(self, pattern_result: RecognizerResult, text: str) -> Optional[RecognizerResult]:
        """Validate the TNIN check digit."""
        matched_text = text[pattern_result.start:pattern_result.end]
        digits_only = re.sub(r"[^\d]", "", matched_text)

        if len(digits_only) != 13:
            return self.invalidate_result(pattern_result)

        # First digit must be 1-8
        if digits_only[0] == "0" or digits_only[0] == "9":
            return self.invalidate_result(pattern_result)

        if not self._validate_check_digit(digits_only):
            return self.invalidate_result(pattern_result)

        pattern_result.score = min(pattern_result.score + 0.3, 1.0)
        return pattern_result

    def invalidate_result(self, pattern_result: RecognizerResult) -> None:
        """Mark result as invalid."""
        pattern_result.score = 0
        return None
