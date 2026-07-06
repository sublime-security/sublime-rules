from presidio_analyzer import PatternRecognizer, Pattern


class NetherlandsBsnRecognizer(PatternRecognizer):
    """
    Recognizer for Dutch Citizen's Service Numbers (Burgerservicenummer / BSN).

    The BSN is 8 or 9 digits. It uses the "11-test" (elfproef) for validation:
    For a 9-digit BSN (d1 d2 d3 d4 d5 d6 d7 d8 d9):
    (9*d1 + 8*d2 + 7*d3 + 6*d4 + 5*d5 + 4*d6 + 3*d7 + 2*d8 + -1*d9) mod 11 == 0
    Note: the last weight is -1, not +1. The result must be divisible by 11 and cannot be 0.

    Checksum: 11-test (elfproef) validation.

    Card view metadata:
      data_categories: [PII]
      data_types: [Government ID]
      regions: [Netherlands]
      compliance: [GDPR]
      detection_methods: [Presidio, Content analysis]
    """

    PATTERNS = [
        Pattern(
            "netherlands_bsn_9",
            r"\b\d{9}\b",
            0.3,
        ),
        Pattern(
            "netherlands_bsn_8",
            r"\b\d{8}\b",
            0.2,
        ),
        Pattern(
            "netherlands_bsn_formatted",
            r"\b\d{4}[\s.]?\d{2}[\s.]?\d{3}\b",
            0.4,
        ),
    ]

    CONTEXT = [
        "BSN",
        "burgerservicenummer",
        "citizen's service",
        "sofinummer",
        "persoonsnummer",
    ]

    def __init__(self):
        super().__init__(
            supported_entity="NETHERLANDS_BSN",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
            supported_language="en",
        )

    def validate_result(self, pattern_text: str) -> bool:
        """Validate using the Dutch 11-test (elfproef) algorithm."""
        cleaned = pattern_text.replace(" ", "").replace(".", "").replace("-", "")

        # BSN can be 8 or 9 digits; pad 8-digit to 9 with leading zero
        if len(cleaned) == 8:
            cleaned = "0" + cleaned
        elif len(cleaned) != 9:
            return False

        try:
            digits = [int(d) for d in cleaned]
        except ValueError:
            return False

        # BSN cannot be all zeros
        if all(d == 0 for d in digits):
            return False

        # 11-test: weights are 9,8,7,6,5,4,3,2,-1
        weights = [9, 8, 7, 6, 5, 4, 3, 2, -1]
        total = sum(d * w for d, w in zip(digits, weights))

        return total % 11 == 0 and total != 0

    def invalidate_result(self, pattern_text: str) -> bool:
        """Check for known false positive patterns."""
        cleaned = pattern_text.replace(" ", "").replace(".", "")
        # All same digits is not a real BSN
        if len(set(cleaned)) <= 1:
            return True
        return False
