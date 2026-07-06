"""
Greece Tax Identification Number (AFM) Recognizer

Detects Greek AFM numbers: 9 digits.
Implements check digit validation using powers of 2.

Card view metadata:
  data_categories: [PII]
  data_types: [Tax ID]
  regions: [Greece]
  compliance: [GDPR]
  detection_methods: [Presidio, Content analysis]
"""

from presidio_analyzer import Pattern, PatternRecognizer, RecognizerResult


class GrTaxIdRecognizer(PatternRecognizer):
    """Recognizer for Greek Tax Identification Numbers (AFM)."""

    PATTERNS = [
        Pattern(
            "gr_tax_id",
            r"\b\d{9}\b",
            0.2,
        ),
    ]

    CONTEXT = [
        "AFM", "tax identification", "greece", "greek",
        "arithmos forologikou mitroou", "tax ID", "TIN",
    ]

    def __init__(self):
        super().__init__(
            supported_entity="GR_TAX_ID",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
            supported_language="en",
        )

    def validate_result(self, pattern_text: str) -> RecognizerResult | None:
        """Validate Greek AFM check digit.

        For each of the first 8 digits, multiply by 2^(8-position).
        Sum mod 11 mod 10 = check digit (last digit).
        """
        digits = [int(c) for c in pattern_text if c.isdigit()]
        if len(digits) != 9:
            return None

        total = 0
        for i in range(8):
            total += digits[i] * (2 ** (8 - i))

        check = (total % 11) % 10
        if check != digits[8]:
            return None
        return None

    def invalidate_result(self, pattern_text: str) -> bool:
        """Filter out obvious false positives."""
        digits = [int(c) for c in pattern_text if c.isdigit()]
        if len(digits) != 9:
            return True
        if len(set(digits)) == 1:
            return True
        # AFM should not start with 0
        if digits[0] == 0:
            return True
        return False
