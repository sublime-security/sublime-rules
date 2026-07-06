"""
Czech Personal Identity Number (Rodne cislo) Recognizer

Detects Czech personal identity numbers: 9-10 digits in XXXXXX/XXXX format.
The full 10-digit number must be divisible by 11.

Card view metadata:
  data_categories: [PII]
  data_types: [Government ID]
  regions: [Czech Republic]
  compliance: [GDPR]
  detection_methods: [Presidio, Content analysis]
"""

from presidio_analyzer import Pattern, PatternRecognizer, RecognizerResult


class CzPersonalIdRecognizer(PatternRecognizer):
    """Recognizer for Czech Personal Identity Numbers (rodne cislo)."""

    PATTERNS = [
        Pattern(
            "cz_personal_id_formatted",
            r"\b(\d{2})(0[1-9]|1[0-2]|5[1-9]|6[0-2])(\d{2})[/\s]?(\d{3,4})\b",
            0.5,
        ),
    ]

    CONTEXT = [
        "rodne cislo", "personal identity", "birth number",
        "czech", "czech republic", "rodne cislo",
    ]

    def __init__(self):
        super().__init__(
            supported_entity="CZ_PERSONAL_ID",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
            supported_language="en",
        )

    def validate_result(self, pattern_text: str) -> RecognizerResult | None:
        """Validate Czech personal ID using mod 11 divisibility.

        For numbers born after 1954 (10 digits): the full number
        must be divisible by 11.
        For 9-digit numbers (born before 1954): no check digit.
        Month can be 01-12 (male) or 51-62 (female).
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
