"""
Argentina CUIT/CUIL Recognizer

Detects Argentine tax identification numbers:
- CUIT (Clave Unica de Identificacion Tributaria) — for businesses
- CUIL (Codigo Unico de Identificacion Laboral) — for individuals

Format: XX-XXXXXXXX-X (11 digits). The first 2 digits indicate the type
(20, 23, 24, 27 for individuals; 30, 33, 34 for companies). The middle
8 digits are the DNI. The last digit is a check digit computed using
weighted sum modulo 11.

Card view metadata:
  data_categories: [Financial]
  data_types: [Tax ID]
  regions: [Argentina]
  compliance: []
  detection_methods: [Presidio, Content analysis]
"""

import re
from typing import Optional

from presidio_analyzer import Pattern, PatternRecognizer
from presidio_analyzer import RecognizerResult


class ArCuitCuilRecognizer(PatternRecognizer):
    """Recognizer for Argentina CUIT/CUIL."""

    PATTERNS = [
        Pattern(
            "ar_cuit_cuil_formatted",
            r"\b(?:20|23|24|27|30|33|34)-\d{8}-\d\b",
            0.7,
        ),
        Pattern(
            "ar_cuit_cuil_compact",
            r"\b(?:20|23|24|27|30|33|34)\d{9}\b",
            0.4,
        ),
    ]

    CONTEXT = [
        "CUIT",
        "CUIL",
        "clave unica",
        "identificacion tributaria",
        "tax ID",
        "argentina",
        "AFIP",
    ]

    _WEIGHTS = [5, 4, 3, 2, 7, 6, 5, 4, 3, 2]

    def __init__(self, **kwargs):
        super().__init__(
            supported_entity="AR_CUIT_CUIL",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
            supported_language="en",
            **kwargs,
        )

    def _validate_check_digit(self, digits_str: str) -> bool:
        """Validate the CUIT/CUIL check digit.

        Algorithm:
        1. Multiply first 10 digits by weights [5,4,3,2,7,6,5,4,3,2].
        2. Sum products.
        3. remainder = 11 - (sum mod 11).
        4. If remainder == 11: check digit = 0.
           If remainder == 10: check digit = 9 (for type 23) or invalid.
           Else: check digit = remainder.
        """
        digits = [int(c) for c in digits_str]
        total = sum(d * w for d, w in zip(digits[:10], self._WEIGHTS))
        remainder = 11 - (total % 11)

        if remainder == 11:
            expected = 0
        elif remainder == 10:
            expected = 9
        else:
            expected = remainder

        return digits[10] == expected

    def validate_result(self, pattern_result: RecognizerResult, text: str) -> Optional[RecognizerResult]:
        """Validate the CUIT/CUIL check digit."""
        matched_text = text[pattern_result.start:pattern_result.end]
        digits_only = re.sub(r"[^\d]", "", matched_text)

        if len(digits_only) != 11:
            return self.invalidate_result(pattern_result)

        # Validate type prefix
        prefix = digits_only[:2]
        if prefix not in ("20", "23", "24", "27", "30", "33", "34"):
            return self.invalidate_result(pattern_result)

        if not self._validate_check_digit(digits_only):
            return self.invalidate_result(pattern_result)

        pattern_result.score = min(pattern_result.score + 0.25, 1.0)
        return pattern_result

    def invalidate_result(self, pattern_result: RecognizerResult) -> None:
        """Mark result as invalid."""
        pattern_result.score = 0
        return None
