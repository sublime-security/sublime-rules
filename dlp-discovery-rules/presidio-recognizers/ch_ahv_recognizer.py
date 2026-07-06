"""
Switzerland Social Security Number (AHV/AVS) Recognizer

Detects Swiss AHV numbers: 13 digits in format 756.XXXX.XXXX.XX.
Always starts with 756 (Switzerland country code).
Implements EAN-13 check digit validation.

Card view metadata:
  data_categories: [PII]
  data_types: [Social Security Number]
  regions: [Switzerland]
  compliance: [GDPR]
  detection_methods: [Presidio, Content analysis]
"""

from presidio_analyzer import Pattern, PatternRecognizer, RecognizerResult


class ChAhvRecognizer(PatternRecognizer):
    """Recognizer for Swiss AHV/AVS Numbers."""

    PATTERNS = [
        Pattern(
            "ch_ahv_formatted",
            r"\b756[\.\s]?\d{4}[\.\s]?\d{4}[\.\s]?\d{2}\b",
            0.7,
        ),
        Pattern(
            "ch_ahv_continuous",
            r"\b756\d{10}\b",
            0.5,
        ),
    ]

    CONTEXT = [
        "AHV", "AVS", "social security", "switzerland", "swiss",
        "sozialversicherungsnummer", "OASI", "AHV-Nummer",
    ]

    def __init__(self):
        super().__init__(
            supported_entity="CH_AHV",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
            supported_language="en",
        )

    def validate_result(self, pattern_text: str) -> RecognizerResult | None:
        """Validate Swiss AHV check digit using EAN-13 algorithm.

        Alternate weights of 1 and 3 for first 12 digits.
        Check digit = (10 - (sum mod 10)) mod 10.
        """
        digits = [int(c) for c in pattern_text if c.isdigit()]
        if len(digits) != 13:
            return None

        # Must start with 756
        if digits[0] != 7 or digits[1] != 5 or digits[2] != 6:
            return None

        total = 0
        for i in range(12):
            weight = 1 if i % 2 == 0 else 3
            total += digits[i] * weight

        check = (10 - (total % 10)) % 10
        if check != digits[12]:
            return None
        return None

    def invalidate_result(self, pattern_text: str) -> bool:
        """Filter out obvious false positives."""
        digits = [int(c) for c in pattern_text if c.isdigit()]
        if len(digits) != 13:
            return True
        if digits[0] != 7 or digits[1] != 5 or digits[2] != 6:
            return True
        return False
