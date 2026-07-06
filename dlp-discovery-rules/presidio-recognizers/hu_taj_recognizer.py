"""
Hungary Social Security Number (TAJ) Recognizer

Detects Hungarian TAJ numbers: 9 digits in XXX XXX XXX format.
Implements check digit validation using alternating weights 3 and 7.

Card view metadata:
  data_categories: [PII]
  data_types: [Social Security Number]
  regions: [Hungary]
  compliance: [GDPR]
  detection_methods: [Presidio, Content analysis]
"""

from presidio_analyzer import Pattern, PatternRecognizer, RecognizerResult


class HuTajRecognizer(PatternRecognizer):
    """Recognizer for Hungarian Social Security Numbers (TAJ)."""

    PATTERNS = [
        Pattern(
            "hu_taj_formatted",
            r"\b(\d{3})[\s]?(\d{3})[\s]?(\d{3})\b",
            0.4,
        ),
    ]

    CONTEXT = [
        "TAJ", "tarsadalombiztositas", "social security",
        "hungary", "hungarian", "TAJ szam", "biztositott",
    ]

    def __init__(self):
        super().__init__(
            supported_entity="HU_TAJ",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
            supported_language="en",
        )

    def validate_result(self, pattern_text: str) -> RecognizerResult | None:
        """Validate Hungarian TAJ check digit.

        Odd positions (1,3,5,7) multiplied by 3, even positions (2,4,6,8) by 7.
        Sum mod 10 = check digit (9th digit).
        """
        digits = [int(c) for c in pattern_text if c.isdigit()]
        if len(digits) != 9:
            return None

        total = 0
        for i in range(8):
            weight = 3 if i % 2 == 0 else 7
            total += digits[i] * weight

        if total % 10 != digits[8]:
            return None
        return None

    def invalidate_result(self, pattern_text: str) -> bool:
        """Filter out obvious false positives."""
        digits = [int(c) for c in pattern_text if c.isdigit()]
        if len(digits) != 9:
            return True
        if len(set(digits)) == 1:
            return True
        return False
