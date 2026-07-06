"""
South Africa National ID Recognizer

Detects South African National Identity Numbers — 13-digit numbers with
format YYMMDD SSSS C A Z where:
- YYMMDD = date of birth
- SSSS = sequence number (5000+ for males, 0-4999 for females)
- C = citizenship (0=SA citizen, 1=permanent resident)
- A = usually 8 (deprecated race indicator)
- Z = Luhn check digit

Card view metadata:
  data_categories: [PII]
  data_types: [Government ID]
  regions: [South Africa]
  compliance: []
  detection_methods: [Presidio, Content analysis]
"""

import re
from typing import Optional

from presidio_analyzer import Pattern, PatternRecognizer
from presidio_analyzer import RecognizerResult


class ZaNationalIdRecognizer(PatternRecognizer):
    """Recognizer for South Africa National Identity Number."""

    PATTERNS = [
        Pattern(
            "za_national_id_spaced",
            r"\b\d{6}[\s]\d{4}[\s]\d[\s]\d[\s]\d\b",
            0.5,
        ),
        Pattern(
            "za_national_id_compact",
            r"\b\d{13}\b",
            0.2,
        ),
    ]

    CONTEXT = [
        "south africa",
        "national ID",
        "ID number",
        "identity number",
        "RSA",
        "SA ID",
        "citizen",
    ]

    def __init__(self, **kwargs):
        super().__init__(
            supported_entity="ZA_NATIONAL_ID",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
            supported_language="en",
            **kwargs,
        )

    @staticmethod
    def _luhn_check(digits_str: str) -> bool:
        """Validate using the Luhn algorithm.

        Starting from the rightmost digit (check digit), double every second
        digit moving left. If doubled value > 9, subtract 9. Sum all digits.
        Valid if sum mod 10 == 0.
        """
        digits = [int(c) for c in digits_str]
        total = 0
        for i, d in enumerate(reversed(digits)):
            if i % 2 == 1:
                d *= 2
                if d > 9:
                    d -= 9
            total += d
        return total % 10 == 0

    @staticmethod
    def _validate_date(digits_str: str) -> bool:
        """Validate the birth date portion (YYMMDD) of the ID."""
        try:
            month = int(digits_str[2:4])
            day = int(digits_str[4:6])
        except ValueError:
            return False

        if month < 1 or month > 12:
            return False
        if day < 1 or day > 31:
            return False
        return True

    def validate_result(self, pattern_result: RecognizerResult, text: str) -> Optional[RecognizerResult]:
        """Validate the South African ID using Luhn check and date validation."""
        matched_text = text[pattern_result.start:pattern_result.end]
        digits_only = re.sub(r"[^\d]", "", matched_text)

        if len(digits_only) != 13:
            return self.invalidate_result(pattern_result)

        # Validate birth date
        if not self._validate_date(digits_only):
            return self.invalidate_result(pattern_result)

        # Validate citizenship digit (position 10, 0-indexed): must be 0 or 1
        if digits_only[10] not in ("0", "1"):
            return self.invalidate_result(pattern_result)

        # Validate Luhn check digit
        if not self._luhn_check(digits_only):
            return self.invalidate_result(pattern_result)

        pattern_result.score = min(pattern_result.score + 0.35, 1.0)
        return pattern_result

    def invalidate_result(self, pattern_result: RecognizerResult) -> None:
        """Mark result as invalid."""
        pattern_result.score = 0
        return None
