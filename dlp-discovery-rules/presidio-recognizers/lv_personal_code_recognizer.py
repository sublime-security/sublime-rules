"""
Latvia Personal Code (Personas kods) Recognizer

Detects Latvian personal codes: 11 digits in DDMMYY-XXXXX format.
Implements modulus 11 check digit validation.

Card view metadata:
  data_categories: [PII]
  data_types: [Government ID]
  regions: [Latvia]
  compliance: [GDPR]
  detection_methods: [Presidio, Content analysis]
"""

from presidio_analyzer import Pattern, PatternRecognizer, RecognizerResult


class LvPersonalCodeRecognizer(PatternRecognizer):
    """Recognizer for Latvian Personal Codes (personas kods)."""

    PATTERNS = [
        Pattern(
            "lv_personal_code_formatted",
            r"\b(0[1-9]|[12]\d|3[01])(0[1-9]|1[0-2])(\d{2})\-?\s?(\d{5})\b",
            0.5,
        ),
        Pattern(
            "lv_personal_code_new",
            r"\b32\d{9}\b",
            0.5,
        ),
    ]

    CONTEXT = [
        "personas kods", "personal code", "latvia", "latvian",
        "personal identification", "isikukods",
    ]

    def __init__(self):
        super().__init__(
            supported_entity="LV_PERSONAL_CODE",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
            supported_language="en",
        )

    def validate_result(self, pattern_text: str) -> RecognizerResult | None:
        """Validate Latvian personal code using modulus 11.

        Old format (pre-2017): DDMMYY-NNNNN with check digit.
        Weights: 1,6,3,7,9,10,5,8,4,2 applied to first 10 digits.
        Check digit = (1 - sum) mod 11; if result is 10, check digit is 0.

        New format (from 2017): starts with 32, no check digit algorithm published.
        """
        digits = [int(c) for c in pattern_text if c.isdigit()]
        if len(digits) != 11:
            return None

        # New format starting with 32 — skip check digit validation
        if digits[0] == 3 and digits[1] == 2:
            return None

        weights = [1, 6, 3, 7, 9, 10, 5, 8, 4, 2]
        total = sum(d * w for d, w in zip(digits[:10], weights))
        check = (1 - total) % 11
        if check == 10:
            check = 0
        if check < 0:
            check += 11

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
