"""
Norway Identification Number (Fodselsnummer) Recognizer

Detects Norwegian ID numbers: 11 digits.
Format: DDMMYYIIIKK where DDMMYY=birth date, III=individual number,
KK=check digits. Two check digits validated using mod 11.

Card view metadata:
  data_categories: [PII]
  data_types: [Government ID]
  regions: [Norway]
  compliance: [GDPR]
  detection_methods: [Presidio, Content analysis]
"""

from presidio_analyzer import Pattern, PatternRecognizer, RecognizerResult


class NoIdentificationNumberRecognizer(PatternRecognizer):
    """Recognizer for Norwegian Identification Numbers (fodselsnummer)."""

    PATTERNS = [
        Pattern(
            "no_id_number",
            r"\b(0[1-9]|[12]\d|3[01])(0[1-9]|1[0-2])\d{7}\b",
            0.5,
        ),
    ]

    CONTEXT = [
        "fodselsnummer", "personal number", "norway", "norwegian",
        "personnummer", "national ID", "fnr",
    ]

    def __init__(self):
        super().__init__(
            supported_entity="NO_IDENTIFICATION_NUMBER",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
            supported_language="en",
        )

    def validate_result(self, pattern_text: str) -> RecognizerResult | None:
        """Validate Norwegian ID number check digits using mod 11.

        Check digit 1 (d10): weights 3,7,6,1,8,9,4,5,2 applied to d1-d9.
        11 - (sum mod 11) = check digit. If 11, check = 0. If 10, invalid.

        Check digit 2 (d11): weights 5,4,3,2,7,6,5,4,3,2 applied to d1-d10.
        Same mod 11 rule.
        """
        digits = [int(c) for c in pattern_text if c.isdigit()]
        if len(digits) != 11:
            return None

        # Check digit 1
        weights1 = [3, 7, 6, 1, 8, 9, 4, 5, 2]
        total1 = sum(d * w for d, w in zip(digits[:9], weights1))
        check1 = 11 - (total1 % 11)
        if check1 == 11:
            check1 = 0
        if check1 == 10:
            return None  # invalid
        if check1 != digits[9]:
            return None

        # Check digit 2
        weights2 = [5, 4, 3, 2, 7, 6, 5, 4, 3, 2]
        total2 = sum(d * w for d, w in zip(digits[:10], weights2))
        check2 = 11 - (total2 % 11)
        if check2 == 11:
            check2 = 0
        if check2 == 10:
            return None  # invalid
        if check2 != digits[10]:
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
