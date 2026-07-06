"""
Romania Personal Numerical Code (CNP) Recognizer

Detects Romanian CNP numbers: 13 digits starting with 1-8.
Format: SYYMMDDCCSSSC where S=sex/century, YYMMDD=birth date,
CC=county, SSS=sequence, C=check digit.

Card view metadata:
  data_categories: [PII]
  data_types: [Government ID]
  regions: [Romania]
  compliance: [GDPR]
  detection_methods: [Presidio, Content analysis]
"""

from presidio_analyzer import Pattern, PatternRecognizer, RecognizerResult


class RoPersonalCodeRecognizer(PatternRecognizer):
    """Recognizer for Romanian Personal Numerical Codes (CNP)."""

    PATTERNS = [
        Pattern(
            "ro_cnp",
            r"\b[1-8]\d{2}(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])\d{6}\b",
            0.5,
        ),
    ]

    CONTEXT = [
        "CNP", "cod numeric personal", "personal code",
        "romania", "romanian", "personal numerical code",
    ]

    def __init__(self):
        super().__init__(
            supported_entity="RO_PERSONAL_CODE",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
            supported_language="en",
        )

    def validate_result(self, pattern_text: str) -> RecognizerResult | None:
        """Validate Romanian CNP check digit.

        Constant: 2,7,9,1,4,6,3,5,8,2,7,9
        Sum of (digit[i] * constant[i]) mod 11.
        If remainder is 10, check digit is 1; otherwise it equals the remainder.
        """
        digits = [int(c) for c in pattern_text if c.isdigit()]
        if len(digits) != 13:
            return None

        constant = [2, 7, 9, 1, 4, 6, 3, 5, 8, 2, 7, 9]
        total = sum(d * c for d, c in zip(digits[:12], constant))
        remainder = total % 11
        check = 1 if remainder == 10 else remainder

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
