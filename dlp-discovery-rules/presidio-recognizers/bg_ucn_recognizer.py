"""
Bulgaria Uniform Civil Number (EGN) Recognizer

Detects Bulgarian UCN numbers: 10 digits.
Format: YYMMDDSSSC where YYMMDD=birth date, SSS=sequence, C=check digit.
Implements weighted checksum validation.

Card view metadata:
  data_categories: [PII]
  data_types: [Government ID]
  regions: [Bulgaria]
  compliance: [GDPR]
  detection_methods: [Presidio, Content analysis]
"""

from presidio_analyzer import Pattern, PatternRecognizer, RecognizerResult


class BgUcnRecognizer(PatternRecognizer):
    """Recognizer for Bulgarian Uniform Civil Numbers (EGN)."""

    PATTERNS = [
        Pattern(
            "bg_ucn",
            r"\b\d{2}(0[1-9]|1[0-2]|2[1-9]|3[0-2]|4[1-9]|5[0-2])(0[1-9]|[12]\d|3[01])\d{4}\b",
            0.5,
        ),
    ]

    CONTEXT = [
        "EGN", "uniform civil", "personal number",
        "bulgaria", "bulgarian", "edinen grazhdanski nomer",
    ]

    def __init__(self):
        super().__init__(
            supported_entity="BG_UCN",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
            supported_language="en",
        )

    def validate_result(self, pattern_text: str) -> RecognizerResult | None:
        """Validate Bulgarian EGN check digit.

        Weights: 2,4,8,5,10,9,7,3,6
        Sum of (digit[i] * weight[i]) mod 11.
        If remainder is 10, check digit is 0; otherwise equals remainder.
        Month encoding: 01-12 (1900s), 21-32 (1800s), 41-52 (2000s).
        """
        digits = [int(c) for c in pattern_text if c.isdigit()]
        if len(digits) != 10:
            return None

        weights = [2, 4, 8, 5, 10, 9, 7, 3, 6]
        total = sum(d * w for d, w in zip(digits[:9], weights))
        remainder = total % 11
        check = 0 if remainder == 10 else remainder

        if check != digits[9]:
            return None
        return None

    def invalidate_result(self, pattern_text: str) -> bool:
        """Filter out obvious false positives."""
        digits = [int(c) for c in pattern_text if c.isdigit()]
        if len(digits) != 10:
            return True
        if len(set(digits)) <= 2:
            return True
        return False
