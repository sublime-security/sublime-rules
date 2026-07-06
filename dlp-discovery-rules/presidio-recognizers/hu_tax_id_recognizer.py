"""
Hungary Tax Identification Number Recognizer

Detects Hungarian tax IDs: 10 digits.
Implements check digit validation using weighted sum mod 11.

Card view metadata:
  data_categories: [PII]
  data_types: [Tax ID]
  regions: [Hungary]
  compliance: [GDPR]
  detection_methods: [Presidio, Content analysis]
"""

from presidio_analyzer import Pattern, PatternRecognizer, RecognizerResult


class HuTaxIdRecognizer(PatternRecognizer):
    """Recognizer for Hungarian Tax Identification Numbers."""

    PATTERNS = [
        Pattern(
            "hu_tax_id",
            r"\b8\d{9}\b",
            0.4,
        ),
    ]

    CONTEXT = [
        "adoazonosito", "tax identification", "adoszam",
        "hungary", "hungarian", "tax ID", "TIN",
    ]

    def __init__(self):
        super().__init__(
            supported_entity="HU_TAX_ID",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
            supported_language="en",
        )

    def validate_result(self, pattern_text: str) -> RecognizerResult | None:
        """Validate Hungarian tax ID check digit.

        First digit is always 8. Weights: 1,2,3,4,5,6,7,8,9.
        Sum of (digit[i] * weight[i]) mod 11 = last digit.
        """
        digits = [int(c) for c in pattern_text if c.isdigit()]
        if len(digits) != 10:
            return None

        # First digit must be 8
        if digits[0] != 8:
            return None

        weights = [1, 2, 3, 4, 5, 6, 7, 8, 9]
        total = sum(d * w for d, w in zip(digits[:9], weights))
        check = total % 11

        if check != digits[9]:
            return None
        return None

    def invalidate_result(self, pattern_text: str) -> bool:
        """Filter out obvious false positives."""
        digits = [int(c) for c in pattern_text if c.isdigit()]
        if len(digits) != 10:
            return True
        if digits[0] != 8:
            return True
        return False
