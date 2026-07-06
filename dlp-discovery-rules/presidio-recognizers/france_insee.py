from presidio_analyzer import PatternRecognizer, Pattern


class FranceInseeRecognizer(PatternRecognizer):
    """
    Recognizer for French Social Security Numbers (INSEE/NIR).

    The INSEE number is 15 digits: sex (1) + birth year (2) + birth month (2)
    + department (2) + commune (3) + order number (3) + check key (2).
    The check key = 97 - (first 13 digits mod 97).
    For Corsica departments (2A, 2B), replace A with 0 and B with 0 before calculation,
    and subtract 1000000 or 2000000 respectively.

    Checksum: Modulo 97 check key validation.

    Card view metadata:
      data_categories: [PII]
      data_types: [Government ID]
      regions: [France]
      compliance: [GDPR]
      detection_methods: [Presidio, Content analysis]
    """

    PATTERNS = [
        Pattern(
            "france_insee_standard",
            r"\b[1-378]\s?\d{2}\s?\d{2}\s?\d{2}\s?\d{3}\s?\d{3}\s?\d{2}\b",
            0.5,
        ),
        Pattern(
            "france_insee_corsica",
            r"\b[1-378]\s?\d{2}\s?\d{2}\s?2[AB]\s?\d{3}\s?\d{3}\s?\d{2}\b",
            0.5,
        ),
    ]

    CONTEXT = [
        "securite sociale",
        "INSEE",
        "NIR",
        "numero de securite sociale",
        "social security",
        "secu",
    ]

    def __init__(self):
        super().__init__(
            supported_entity="FRANCE_INSEE",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
            supported_language="en",
        )

    def validate_result(self, pattern_text: str) -> bool:
        """Validate using modulo 97 check key algorithm."""
        # Remove all spaces and non-alphanumeric characters
        cleaned = pattern_text.replace(" ", "").replace(".", "").replace("-", "")

        if len(cleaned) != 15:
            return False

        # Handle Corsica departments (2A and 2B)
        try:
            if "A" in cleaned.upper():
                # Department 2A: replace A, subtract 1000000
                numeric_str = cleaned.upper().replace("A", "0")
                base_number = int(numeric_str[:13]) - 1000000
            elif "B" in cleaned.upper():
                # Department 2B: replace B, subtract 2000000
                numeric_str = cleaned.upper().replace("B", "0")
                base_number = int(numeric_str[:13]) - 2000000
            else:
                base_number = int(cleaned[:13])

            check_key = int(cleaned[13:15])
            expected_key = 97 - (base_number % 97)

            return check_key == expected_key
        except (ValueError, IndexError):
            return False

    def invalidate_result(self, pattern_text: str) -> bool:
        """Check for known false positive patterns."""
        cleaned = pattern_text.replace(" ", "")
        # All same digits is likely not a real INSEE number
        if len(set(cleaned)) <= 2:
            return True
        return False
