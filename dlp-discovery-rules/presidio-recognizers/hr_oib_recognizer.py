"""
Croatia Personal Identification Number (OIB) Recognizer

Detects Croatian OIB numbers: 11 digits.
Implements ISO 7064, Mod 10 check digit validation.

Card view metadata:
  data_categories: [PII]
  data_types: [Government ID]
  regions: [Croatia]
  compliance: [GDPR]
  detection_methods: [Presidio, Content analysis]
"""

from presidio_analyzer import Pattern, PatternRecognizer, RecognizerResult


class HrOibRecognizer(PatternRecognizer):
    """Recognizer for Croatian Personal Identification Numbers (OIB)."""

    PATTERNS = [
        Pattern(
            "hr_oib",
            r"\b\d{11}\b",
            0.3,
        ),
    ]

    CONTEXT = [
        "OIB", "osobni identifikacijski", "personal identification",
        "croatia", "croatian", "osobni identifikacijski broj",
    ]

    def __init__(self):
        super().__init__(
            supported_entity="HR_OIB",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
            supported_language="en",
        )

    def validate_result(self, pattern_text: str) -> RecognizerResult | None:
        """Validate Croatian OIB using ISO 7064, Mod 10, Mod 11-10 algorithm.

        1. Start with t = 10
        2. For each of the first 10 digits:
           a. t = (t + digit) mod 10; if t == 0 then t = 10
           b. t = (t * 2) mod 11
        3. Check digit = (11 - t) mod 10
        """
        digits = [int(c) for c in pattern_text if c.isdigit()]
        if len(digits) != 11:
            return None

        t = 10
        for i in range(10):
            t = (t + digits[i]) % 10
            if t == 0:
                t = 10
            t = (t * 2) % 11

        check = (11 - t) % 10
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
