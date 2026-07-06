"""
Slovakia Personal Number (Rodne cislo) Recognizer

Detects Slovak personal numbers: 9-10 digits in XXXXXX/XXXX format.
The full 10-digit number must be divisible by 11 (same as Czech).

Card view metadata:
  data_categories: [PII]
  data_types: [Government ID]
  regions: [Slovakia]
  compliance: [GDPR]
  detection_methods: [Presidio, Content analysis]
"""

from presidio_analyzer import Pattern, PatternRecognizer, RecognizerResult


class SkPersonalNumberRecognizer(PatternRecognizer):
    """Recognizer for Slovak Personal Numbers (rodne cislo)."""

    PATTERNS = [
        Pattern(
            "sk_personal_number_formatted",
            r"\b(\d{2})(0[1-9]|1[0-2]|5[1-9]|6[0-2])(\d{2})[/\s]?(\d{3,4})\b",
            0.5,
        ),
    ]

    CONTEXT = [
        "rodne cislo", "personal number", "slovakia", "slovak",
        "birth number", "osobne cislo",
    ]

    def __init__(self):
        super().__init__(
            supported_entity="SK_PERSONAL_NUMBER",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
            supported_language="en",
        )

    def validate_result(self, pattern_text: str) -> RecognizerResult | None:
        """Validate Slovak personal number using mod 11 divisibility.

        Same algorithm as Czech rodne cislo: 10-digit numbers must be
        divisible by 11. 9-digit numbers (pre-1954) have no check digit.
        """
        digits = [int(c) for c in pattern_text if c.isdigit()]

        if len(digits) == 10:
            number = int("".join(str(d) for d in digits))
            if number % 11 != 0:
                return None
        elif len(digits) != 9:
            return None

        return None

    def invalidate_result(self, pattern_text: str) -> bool:
        """Filter out obvious false positives."""
        digits = [int(c) for c in pattern_text if c.isdigit()]
        if len(digits) not in (9, 10):
            return True
        if len(set(digits)) <= 2:
            return True
        return False
