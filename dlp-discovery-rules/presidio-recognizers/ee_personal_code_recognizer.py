"""
Estonia Personal Identification Code (Isikukood) Recognizer

Detects Estonian personal codes: 11 digits starting with 1-6.
Format: GYYMMDDSSSC where G=gender/century, YYMMDD=birth date,
SSS=sequence, C=check digit.

Card view metadata:
  data_categories: [PII]
  data_types: [Government ID]
  regions: [Estonia]
  compliance: [GDPR]
  detection_methods: [Presidio, Content analysis]
"""

from presidio_analyzer import Pattern, PatternRecognizer, RecognizerResult


class EePersonalCodeRecognizer(PatternRecognizer):
    """Recognizer for Estonian Personal Identification Codes (isikukood)."""

    PATTERNS = [
        Pattern(
            "ee_personal_code",
            r"\b[1-6]\d{2}(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])\d{4}\b",
            0.5,
        ),
    ]

    CONTEXT = [
        "isikukood", "personal code", "estonia", "estonian",
        "personal identification", "ID code",
    ]

    def __init__(self):
        super().__init__(
            supported_entity="EE_PERSONAL_CODE",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
            supported_language="en",
        )

    def validate_result(self, pattern_text: str) -> RecognizerResult | None:
        """Validate Estonian personal code check digit.

        Stage 1 weights: 1,2,3,4,5,6,7,8,9,1
        Stage 2 weights: 3,4,5,6,7,8,9,1,2,3
        If stage 1 mod 11 == 10, use stage 2. If stage 2 mod 11 == 10, check digit = 0.
        """
        digits = [int(c) for c in pattern_text if c.isdigit()]
        if len(digits) != 11:
            return None

        weights1 = [1, 2, 3, 4, 5, 6, 7, 8, 9, 1]
        checksum = sum(d * w for d, w in zip(digits[:10], weights1)) % 11

        if checksum == 10:
            weights2 = [3, 4, 5, 6, 7, 8, 9, 1, 2, 3]
            checksum = sum(d * w for d, w in zip(digits[:10], weights2)) % 11
            if checksum == 10:
                checksum = 0

        if checksum != digits[10]:
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
