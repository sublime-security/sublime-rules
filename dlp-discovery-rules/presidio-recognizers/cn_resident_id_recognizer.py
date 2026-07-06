"""
China Resident Identity Card Recognizer

Detects Chinese Resident Identity Card numbers (居民身份证号码).
18-digit format: 6-digit area code + 8-digit birth date (YYYYMMDD) +
3-digit sequence + 1 check digit. The check digit uses a weighted
checksum modulo 11 with remainder mapped to [1,0,X,9,8,7,6,5,4,3,2].

Card view metadata:
  data_categories: [PII]
  data_types: [Government ID]
  regions: [China]
  compliance: []
  detection_methods: [Presidio, Content analysis]
"""

import re
from typing import List, Optional

from presidio_analyzer import Pattern, PatternRecognizer
from presidio_analyzer import RecognizerResult


class CnResidentIdRecognizer(PatternRecognizer):
    """Recognizer for China Resident Identity Card Number (居民身份证号码)."""

    PATTERNS = [
        Pattern(
            "cn_resident_id_18",
            r"\b\d{17}[\dXx]\b",
            0.4,
        ),
        Pattern(
            "cn_resident_id_15",
            r"\b\d{15}\b",
            0.1,
        ),
    ]

    CONTEXT = [
        "resident ID",
        "identity card",
        "身份证",
        "身份证号",
        "居民身份证",
        "chinese ID",
        "china",
        "ID number",
    ]

    # Weights for positions 1-17
    _WEIGHTS = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2]
    # Check digit mapping: remainder -> check character
    _CHECK_MAP = "10X98765432"

    def __init__(self, **kwargs):
        super().__init__(
            supported_entity="CN_RESIDENT_ID",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
            supported_language="en",
            **kwargs,
        )

    @staticmethod
    def _validate_date(year: int, month: int, day: int) -> bool:
        """Basic validation of birth date components."""
        if month < 1 or month > 12:
            return False
        if day < 1 or day > 31:
            return False
        if year < 1900 or year > 2100:
            return False
        return True

    def _compute_check_char(self, digits: List[int]) -> str:
        """Compute the check character for an 18-digit ID from the first 17 digits."""
        total = sum(d * w for d, w in zip(digits, self._WEIGHTS))
        remainder = total % 11
        return self._CHECK_MAP[remainder]

    def validate_result(self, pattern_result: RecognizerResult, text: str) -> Optional[RecognizerResult]:
        """Validate the Chinese Resident ID check digit and date."""
        matched_text = text[pattern_result.start:pattern_result.end]
        matched_upper = matched_text.upper()

        if len(matched_upper) == 18:
            # Validate birth date (positions 6-13: YYYYMMDD)
            try:
                year = int(matched_upper[6:10])
                month = int(matched_upper[10:12])
                day = int(matched_upper[12:14])
            except ValueError:
                return self.invalidate_result(pattern_result)

            if not self._validate_date(year, month, day):
                return self.invalidate_result(pattern_result)

            # Validate check digit
            digits = [int(c) for c in matched_upper[:17]]
            expected_check = self._compute_check_char(digits)

            if matched_upper[17] != expected_check:
                return self.invalidate_result(pattern_result)

            # Valid — boost confidence
            pattern_result.score = min(pattern_result.score + 0.4, 1.0)
            return pattern_result

        elif len(matched_upper) == 15:
            # 15-digit legacy format: no check digit, validate birth date (YYMMDD at pos 6-11)
            try:
                year = int("19" + matched_upper[6:8])
                month = int(matched_upper[8:10])
                day = int(matched_upper[10:12])
            except ValueError:
                return self.invalidate_result(pattern_result)

            if not self._validate_date(year, month, day):
                return self.invalidate_result(pattern_result)

            pattern_result.score = min(pattern_result.score + 0.2, 1.0)
            return pattern_result

        return self.invalidate_result(pattern_result)

    def invalidate_result(self, pattern_result: RecognizerResult) -> None:
        """Mark result as invalid."""
        pattern_result.score = 0
        return None
