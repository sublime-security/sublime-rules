from presidio_analyzer import PatternRecognizer, Pattern


class PortugalTaxIdRecognizer(PatternRecognizer):
    """
    Recognizer for Portuguese Tax Identification Numbers (NIF).

    The NIF is 9 digits. The first digit indicates the type of entity:
    1-3 = individual, 5 = legal entity, 6 = public entity, 8 = sole proprietor.

    Checksum: The 9th digit is a check digit computed using a weighted modulo 11 algorithm.
    Weights are [9, 8, 7, 6, 5, 4, 3, 2] applied to the first 8 digits.
    Sum of (digit * weight), then check = 11 - (sum mod 11). If result >= 10, check digit = 0.

    Card view metadata:
      data_categories: [PII]
      data_types: [Tax]
      regions: [Portugal]
      compliance: [GDPR]
      detection_methods: [Presidio, Content analysis]
    """

    PATTERNS = [
        Pattern(
            "portugal_nif",
            r"\b[1-3,5,6,8]\d{8}\b",
            0.5,
        ),
        Pattern(
            "portugal_nif_formatted",
            r"\b[1-3,5,6,8]\d{2}[\s.]?\d{3}[\s.]?\d{3}\b",
            0.5,
        ),
    ]

    CONTEXT = [
        "NIF",
        "numero de identificacao fiscal",
        "tax ID",
        "contribuinte",
        "numero fiscal",
    ]

    def __init__(self):
        super().__init__(
            supported_entity="PORTUGAL_TAX_ID",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
            supported_language="en",
        )

    def validate_result(self, pattern_text: str) -> bool:
        """Validate using the Portuguese NIF modulo 11 check digit algorithm."""
        # Remove spaces, dots, hyphens
        cleaned = pattern_text.replace(" ", "").replace(".", "").replace("-", "")

        if len(cleaned) != 9:
            return False

        try:
            digits = [int(d) for d in cleaned]
        except ValueError:
            return False

        # Weights for positions 1-8
        weights = [9, 8, 7, 6, 5, 4, 3, 2]

        # Calculate weighted sum
        total = sum(d * w for d, w in zip(digits[:8], weights))

        # Check digit calculation
        remainder = total % 11
        if remainder < 2:
            expected_check = 0
        else:
            expected_check = 11 - remainder

        return digits[8] == expected_check

    def invalidate_result(self, pattern_text: str) -> bool:
        """Check for known false positive patterns."""
        cleaned = pattern_text.replace(" ", "").replace(".", "")
        # All same digits is likely not valid
        if len(set(cleaned)) <= 1:
            return True
        return False
