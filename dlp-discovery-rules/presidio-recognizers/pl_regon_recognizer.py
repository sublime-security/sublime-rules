"""
Poland REGON Number Recognizer

Detects Polish REGON numbers: 9 or 14 digits.
Statistical identification number for businesses.
Implements check digit validation using weighted sum.

Card view metadata:
  data_categories: [PII]
  data_types: [Business Registration]
  regions: [Poland]
  compliance: [GDPR]
  detection_methods: [Presidio, Content analysis]
"""

from presidio_analyzer import Pattern, PatternRecognizer, RecognizerResult


class PlRegonRecognizer(PatternRecognizer):
    """Recognizer for Polish REGON Numbers."""

    PATTERNS = [
        Pattern(
            "pl_regon_9",
            r"\b\d{9}\b",
            0.2,
        ),
        Pattern(
            "pl_regon_14",
            r"\b\d{14}\b",
            0.3,
        ),
    ]

    CONTEXT = [
        "REGON", "poland", "polish", "statistical number",
        "rejestr gospodarki narodowej", "business registration",
    ]

    def __init__(self):
        super().__init__(
            supported_entity="PL_REGON",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
            supported_language="en",
        )

    def validate_result(self, pattern_text: str) -> RecognizerResult | None:
        """Validate Polish REGON check digit.

        9-digit REGON: weights 8,9,2,3,4,5,6,7. Sum mod 11; if 10 then check=0.
        14-digit REGON: weights 2,4,8,5,0,9,7,3,6,1,2,4,8. Same approach.
        """
        digits = [int(c) for c in pattern_text if c.isdigit()]

        if len(digits) == 9:
            weights = [8, 9, 2, 3, 4, 5, 6, 7]
            total = sum(d * w for d, w in zip(digits[:8], weights))
            check = total % 11
            if check == 10:
                check = 0
            if check != digits[8]:
                return None
        elif len(digits) == 14:
            weights = [2, 4, 8, 5, 0, 9, 7, 3, 6, 1, 2, 4, 8]
            total = sum(d * w for d, w in zip(digits[:13], weights))
            check = total % 11
            if check == 10:
                check = 0
            if check != digits[13]:
                return None
        else:
            return None

        return None

    def invalidate_result(self, pattern_text: str) -> bool:
        """Filter out obvious false positives."""
        digits = [int(c) for c in pattern_text if c.isdigit()]
        if len(digits) not in (9, 14):
            return True
        if len(set(digits)) <= 2:
            return True
        return False
