"""
Brazil CPF (Cadastro de Pessoas Fisicas) Recognizer

Detects Brazilian CPF numbers — 11-digit tax identification numbers for
individuals. Validated using a mod-11 checksum algorithm on two check
digits (positions 10 and 11).

Card view metadata:
  data_categories: [Financial]
  data_types: [Tax ID]
  regions: [Brazil]
  compliance: []
  detection_methods: [Presidio, Content analysis]
"""

import re
from typing import Optional

from presidio_analyzer import Pattern, PatternRecognizer
from presidio_analyzer import RecognizerResult


class BrCpfRecognizer(PatternRecognizer):
    """Recognizer for Brazil CPF (Cadastro de Pessoas Fisicas)."""

    PATTERNS = [
        Pattern(
            "br_cpf_formatted",
            r"\b\d{3}\.\d{3}\.\d{3}-\d{2}\b",
            0.6,
        ),
        Pattern(
            "br_cpf_compact",
            r"\b\d{11}\b",
            0.15,
        ),
    ]

    CONTEXT = [
        "CPF",
        "cadastro de pessoas",
        "tax ID",
        "brazil",
        "brasil",
        "contribuinte",
    ]

    def __init__(self, **kwargs):
        super().__init__(
            supported_entity="BR_CPF",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
            supported_language="en",
            **kwargs,
        )

    @staticmethod
    def _validate_cpf(cpf_str: str) -> bool:
        """Validate CPF using mod-11 checksum.

        Algorithm:
        1. First check digit: multiply digits 1-9 by weights [10,9,8,...,2],
           sum products, remainder = sum mod 11. If remainder < 2, check = 0;
           else check = 11 - remainder.
        2. Second check digit: multiply digits 1-10 by weights [11,10,9,...,2],
           sum products, remainder = sum mod 11. Same rule for check digit.
        3. Reject sequences of all identical digits (e.g., 111.111.111-11).
        """
        digits = [int(c) for c in cpf_str]

        # Reject all-same digits
        if len(set(digits)) == 1:
            return False

        # First check digit (position 9, 0-indexed)
        weights_1 = list(range(10, 1, -1))  # [10, 9, 8, ..., 2]
        total_1 = sum(d * w for d, w in zip(digits[:9], weights_1))
        remainder_1 = total_1 % 11
        check_1 = 0 if remainder_1 < 2 else 11 - remainder_1

        if digits[9] != check_1:
            return False

        # Second check digit (position 10, 0-indexed)
        weights_2 = list(range(11, 1, -1))  # [11, 10, 9, ..., 2]
        total_2 = sum(d * w for d, w in zip(digits[:10], weights_2))
        remainder_2 = total_2 % 11
        check_2 = 0 if remainder_2 < 2 else 11 - remainder_2

        return digits[10] == check_2

    def validate_result(self, pattern_result: RecognizerResult, text: str) -> Optional[RecognizerResult]:
        """Validate the CPF checksum."""
        matched_text = text[pattern_result.start:pattern_result.end]
        digits_only = re.sub(r"[^\d]", "", matched_text)

        if len(digits_only) != 11:
            return self.invalidate_result(pattern_result)

        if not self._validate_cpf(digits_only):
            return self.invalidate_result(pattern_result)

        pattern_result.score = min(pattern_result.score + 0.3, 1.0)
        return pattern_result

    def invalidate_result(self, pattern_result: RecognizerResult) -> None:
        """Mark result as invalid."""
        pattern_result.score = 0
        return None
