"""
Mexico CURP (Clave Unica de Registro de Poblacion) Recognizer

Detects Mexican CURP numbers — 18-character alphanumeric identifiers.
Format: AAAA######HSSSCCN#
  - 4 letters (surname/first name initials)
  - 6 digits (YYMMDD birth date)
  - 1 letter (H=male, M=female)
  - 2 letters (state code)
  - 3 consonants (from names)
  - 1 alphanumeric (disambiguator)
  - 1 digit (check digit)

The check digit is computed from a weighted sum of character values.

Card view metadata:
  data_categories: [PII]
  data_types: [Government ID]
  regions: [Mexico]
  compliance: []
  detection_methods: [Presidio, Content analysis]
"""

import re
from typing import Optional

from presidio_analyzer import Pattern, PatternRecognizer
from presidio_analyzer import RecognizerResult


class MxCurpRecognizer(PatternRecognizer):
    """Recognizer for Mexico CURP (Clave Unica de Registro de Poblacion)."""

    PATTERNS = [
        Pattern(
            "mx_curp",
            r"\b[A-Z]{4}\d{6}[HM][A-Z]{5}[0-9A-Z]\d\b",
            0.7,
        ),
    ]

    CONTEXT = [
        "CURP",
        "clave unica",
        "clave única",
        "registro de poblacion",
        "población",
        "mexico",
        "méxico",
    ]

    # Valid Mexican state codes
    _VALID_STATES = {
        "AS", "BC", "BS", "CC", "CL", "CM", "CS", "CH", "DF", "DG",
        "GT", "GR", "HG", "JC", "MC", "MN", "MS", "NT", "NL", "OC",
        "PL", "QT", "QR", "SP", "SL", "SR", "TC", "TS", "TL", "VZ",
        "YN", "ZS", "NE",  # NE = born abroad
    }

    _CHAR_MAP = "0123456789ABCDEFGHIJKLMNÑOPQRSTUVWXYZ"

    def __init__(self, **kwargs):
        super().__init__(
            supported_entity="MX_CURP",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
            supported_language="en",
            **kwargs,
        )

    def _compute_check_digit(self, curp_17: str) -> int:
        """Compute the CURP check digit from the first 17 characters.

        Each character is mapped to a numeric value (0-9 for digits, 10+ for letters).
        Multiply each value by (18 - position) where position is 0-indexed.
        Sum all products. Check digit = (10 - (sum mod 10)) mod 10.
        """
        total = 0
        for i, ch in enumerate(curp_17):
            try:
                val = self._CHAR_MAP.index(ch)
            except ValueError:
                return -1
            total += val * (18 - i)
        return (10 - (total % 10)) % 10

    def validate_result(self, pattern_result: RecognizerResult, text: str) -> Optional[RecognizerResult]:
        """Validate the CURP structure and check digit."""
        matched_text = text[pattern_result.start:pattern_result.end].upper()

        if len(matched_text) != 18:
            return self.invalidate_result(pattern_result)

        # Validate state code (positions 11-12)
        state_code = matched_text[11:13]
        if state_code not in self._VALID_STATES:
            return self.invalidate_result(pattern_result)

        # Validate birth date (positions 4-9: YYMMDD)
        try:
            month = int(matched_text[6:8])
            day = int(matched_text[8:10])
        except ValueError:
            return self.invalidate_result(pattern_result)

        if month < 1 or month > 12 or day < 1 or day > 31:
            return self.invalidate_result(pattern_result)

        # Validate check digit
        expected = self._compute_check_digit(matched_text[:17])
        try:
            actual = int(matched_text[17])
        except ValueError:
            return self.invalidate_result(pattern_result)

        if expected != actual:
            return self.invalidate_result(pattern_result)

        pattern_result.score = min(pattern_result.score + 0.2, 1.0)
        return pattern_result

    def invalidate_result(self, pattern_result: RecognizerResult) -> None:
        """Mark result as invalid."""
        pattern_result.score = 0
        return None
