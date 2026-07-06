"""
Chile CDI (Cedula de Identidad / RUT) Recognizer

Detects Chilean Identity Card numbers (RUN/RUT). Format: XX.XXX.XXX-V
where V is a check digit (0-9 or K). Validated using a weighted sum
modulo 11 algorithm.

Card view metadata:
  data_categories: [PII]
  data_types: [Government ID]
  regions: [Chile]
  compliance: []
  detection_methods: [Presidio, Content analysis]
"""

import re
from typing import Optional

from presidio_analyzer import Pattern, PatternRecognizer
from presidio_analyzer import RecognizerResult


class ClCdiRecognizer(PatternRecognizer):
    """Recognizer for Chile CDI / RUT (Rol Unico Tributario)."""

    PATTERNS = [
        Pattern(
            "cl_cdi_formatted",
            r"\b\d{1,2}\.\d{3}\.\d{3}-[0-9Kk]\b",
            0.6,
        ),
        Pattern(
            "cl_cdi_compact",
            r"\b\d{7,8}[0-9Kk]\b",
            0.2,
        ),
    ]

    CONTEXT = [
        "RUT",
        "RUN",
        "cédula",
        "cedula",
        "identity card",
        "CDI",
        "chile",
        "chilean",
    ]

    def __init__(self, **kwargs):
        super().__init__(
            supported_entity="CL_CDI",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
            supported_language="en",
            **kwargs,
        )

    @staticmethod
    def _compute_check_char(digits_str: str) -> str:
        """Compute the RUT check digit using mod-11 algorithm.

        Multiply digits (right-to-left) by cycling weights [2,3,4,5,6,7].
        Sum products. remainder = 11 - (sum mod 11).
        If remainder == 11: check = '0'
        If remainder == 10: check = 'K'
        Else: check = str(remainder)
        """
        weights = [2, 3, 4, 5, 6, 7]
        total = 0
        for i, ch in enumerate(reversed(digits_str)):
            total += int(ch) * weights[i % 6]
        remainder = 11 - (total % 11)
        if remainder == 11:
            return "0"
        elif remainder == 10:
            return "K"
        return str(remainder)

    def validate_result(self, pattern_result: RecognizerResult, text: str) -> Optional[RecognizerResult]:
        """Validate the Chilean RUT/RUN check digit."""
        matched_text = text[pattern_result.start:pattern_result.end]
        # Remove dots and hyphens
        cleaned = matched_text.replace(".", "").replace("-", "").upper()

        if len(cleaned) < 8 or len(cleaned) > 9:
            return self.invalidate_result(pattern_result)

        body = cleaned[:-1]
        check = cleaned[-1]

        if not body.isdigit():
            return self.invalidate_result(pattern_result)

        expected = self._compute_check_char(body)
        if check != expected:
            return self.invalidate_result(pattern_result)

        pattern_result.score = min(pattern_result.score + 0.3, 1.0)
        return pattern_result

    def invalidate_result(self, pattern_result: RecognizerResult) -> None:
        """Mark result as invalid."""
        pattern_result.score = 0
        return None
