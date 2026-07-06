"""
Slovenia Unique Master Citizen Number (EMSO) Recognizer

Detects Slovenian EMSO numbers: 13 digits.
Format: DDMMYYYRRSSSC where DDMMYYY=birth date (YYY=last 3 of year),
RR=registration region, SSS=sequence, C=check digit.

Card view metadata:
  data_categories: [PII]
  data_types: [Government ID]
  regions: [Slovenia]
  compliance: [GDPR]
  detection_methods: [Presidio, Content analysis]
"""

from presidio_analyzer import Pattern, PatternRecognizer, RecognizerResult


class SiEmsoRecognizer(PatternRecognizer):
    """Recognizer for Slovenian Unique Master Citizen Numbers (EMSO)."""

    PATTERNS = [
        Pattern(
            "si_emso",
            r"\b(0[1-9]|[12]\d|3[01])(0[1-9]|1[0-2])\d{9}\b",
            0.5,
        ),
    ]

    CONTEXT = [
        "EMSO", "maticna stevilka", "unique master citizen",
        "slovenia", "slovenian", "enotna maticna stevilka obcana",
    ]

    def __init__(self):
        super().__init__(
            supported_entity="SI_EMSO",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
            supported_language="en",
        )

    def validate_result(self, pattern_text: str) -> RecognizerResult | None:
        """Validate Slovenian EMSO check digit.

        Weights: 7,6,5,4,3,2,7,6,5,4,3,2
        Sum of (digit[i] * weight[i]) mod 11.
        Check digit = 11 - remainder. If result is 11, check = 0.
        If result is 10, the number is invalid.
        """
        digits = [int(c) for c in pattern_text if c.isdigit()]
        if len(digits) != 13:
            return None

        weights = [7, 6, 5, 4, 3, 2, 7, 6, 5, 4, 3, 2]
        total = sum(d * w for d, w in zip(digits[:12], weights))
        remainder = total % 11
        check = 11 - remainder
        if check == 11:
            check = 0
        if check == 10:
            return None  # invalid number

        if check != digits[12]:
            return None
        return None

    def invalidate_result(self, pattern_text: str) -> bool:
        """Filter out obvious false positives."""
        digits = [int(c) for c in pattern_text if c.isdigit()]
        if len(digits) != 13:
            return True
        if len(set(digits)) <= 2:
            return True
        return False
