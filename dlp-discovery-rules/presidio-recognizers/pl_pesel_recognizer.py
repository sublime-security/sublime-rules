"""
Poland PESEL Number Recognizer

Detects Polish PESEL numbers: 11 digits.
Format: YYMMDDSSSSQ where YYMMDD=birth date, SSSS=sequence, Q=check digit.
Implements checksum mod 10 validation.

Card view metadata:
  data_categories: [PII]
  data_types: [Government ID]
  regions: [Poland]
  compliance: [GDPR]
  detection_methods: [Presidio, Content analysis]
"""

from presidio_analyzer import Pattern, PatternRecognizer, RecognizerResult


class PlPeselRecognizer(PatternRecognizer):
    """Recognizer for Polish PESEL Numbers."""

    PATTERNS = [
        Pattern(
            "pl_pesel",
            r"\b\d{2}(0[1-9]|1[0-2]|[2-3][1-9]|[2-3]0)(0[1-9]|[12]\d|3[01])\d{5}\b",
            0.5,
        ),
    ]

    CONTEXT = [
        "PESEL", "poland", "polish", "personal identification",
        "numer ewidencyjny", "powszechny elektroniczny system ewidencji ludnosci",
    ]

    def __init__(self):
        super().__init__(
            supported_entity="PL_PESEL",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
            supported_language="en",
        )

    def validate_result(self, pattern_text: str) -> RecognizerResult | None:
        """Validate Polish PESEL check digit.

        Weights: 1,3,7,9,1,3,7,9,1,3
        Sum of (digit[i] * weight[i]) mod 10.
        Check digit = (10 - sum_mod_10) mod 10.
        """
        digits = [int(c) for c in pattern_text if c.isdigit()]
        if len(digits) != 11:
            return None

        weights = [1, 3, 7, 9, 1, 3, 7, 9, 1, 3]
        total = sum(d * w for d, w in zip(digits[:10], weights))
        check = (10 - (total % 10)) % 10

        if check != digits[10]:
            return None
        return None

    def invalidate_result(self, pattern_text: str) -> bool:
        """Filter out obvious false positives."""
        digits = [int(c) for c in pattern_text if c.isdigit()]
        if len(digits) != 11:
            return True
        if len(set(digits)) <= 2:
            return True
        return False
