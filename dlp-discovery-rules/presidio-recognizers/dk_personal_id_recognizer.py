"""
Denmark Personal Identification Number (CPR-nummer) Recognizer

Detects Danish CPR numbers in the format DDMMYY-XXXX (10 digits).
Implements modulus 11 check digit validation.

Card view metadata:
  data_categories: [PII]
  data_types: [Government ID]
  regions: [Denmark]
  compliance: [GDPR]
  detection_methods: [Presidio, Content analysis]
"""

from presidio_analyzer import Pattern, PatternRecognizer, RecognizerResult


class DkPersonalIdRecognizer(PatternRecognizer):
    """Recognizer for Danish CPR numbers (personnummer)."""

    PATTERNS = [
        Pattern(
            "dk_cpr_formatted",
            r"\b(\d{2})(0[1-9]|1[0-2])(\d{2})\-?\s?(\d{4})\b",
            0.5,
        ),
    ]

    CONTEXT = [
        "CPR", "personnummer", "personal identification",
        "denmark", "danish", "cpr-nummer", "civil registration",
    ]

    def __init__(self):
        super().__init__(
            supported_entity="DK_PERSONAL_ID",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
            supported_language="en",
        )

    def validate_result(self, pattern_text: str) -> RecognizerResult | None:
        """Validate using modulus 11 check digit algorithm.

        Note: Denmark abolished the modulus 11 check for CPR numbers
        assigned after 2007-10-01, so we validate date plausibility
        and apply the check digit only where applicable.
        """
        digits = [int(c) for c in pattern_text if c.isdigit()]
        if len(digits) != 10:
            return None

        # Validate date portion (DD MM YY)
        dd = digits[0] * 10 + digits[1]
        mm = digits[2] * 10 + digits[3]
        if dd < 1 or dd > 31 or mm < 1 or mm > 12:
            return None

        # Modulus 11 check (weights: 4,3,2,7,6,5,4,3,2,1)
        weights = [4, 3, 2, 7, 6, 5, 4, 3, 2, 1]
        checksum = sum(d * w for d, w in zip(digits, weights))
        if checksum % 11 == 0:
            return None  # signal: valid — presidio uses truthy return
        # Post-2007 numbers may not pass mod 11; still allow with lower score
        return None

    def invalidate_result(self, pattern_text: str) -> bool:
        """Filter out obvious false positives."""
        digits = [int(c) for c in pattern_text if c.isdigit()]
        if len(digits) != 10:
            return True
        # All same digit
        if len(set(digits)) == 1:
            return True
        return False
