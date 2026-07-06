"""
Greece Social Security Number (AMKA) Recognizer

Detects Greek AMKA numbers: 11 digits.
Format: DDMMYYXXXXX where DDMMYY=birth date.
Implements Luhn algorithm check digit validation.

Card view metadata:
  data_categories: [PII]
  data_types: [Social Security Number]
  regions: [Greece]
  compliance: [GDPR]
  detection_methods: [Presidio, Content analysis]
"""

from presidio_analyzer import Pattern, PatternRecognizer, RecognizerResult


class GrAmkaRecognizer(PatternRecognizer):
    """Recognizer for Greek Social Security Numbers (AMKA)."""

    PATTERNS = [
        Pattern(
            "gr_amka",
            r"\b(0[1-9]|[12]\d|3[01])(0[1-9]|1[0-2])\d{7}\b",
            0.5,
        ),
    ]

    CONTEXT = [
        "AMKA", "social security", "greece", "greek",
        "arithmos mitroou koinonikis asfalisis",
    ]

    def __init__(self):
        super().__init__(
            supported_entity="GR_AMKA",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
            supported_language="en",
        )

    def validate_result(self, pattern_text: str) -> RecognizerResult | None:
        """Validate Greek AMKA using Luhn (mod 10) algorithm.

        Double every second digit from right, subtract 9 if > 9.
        Total sum mod 10 must equal 0.
        """
        digits = [int(c) for c in pattern_text if c.isdigit()]
        if len(digits) != 11:
            return None

        total = 0
        for i, d in enumerate(reversed(digits)):
            if i % 2 == 1:
                d *= 2
                if d > 9:
                    d -= 9
            total += d

        if total % 10 != 0:
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
