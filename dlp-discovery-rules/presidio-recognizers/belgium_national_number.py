from presidio_analyzer import PatternRecognizer, Pattern


class BelgiumNationalNumberRecognizer(PatternRecognizer):
    """
    Recognizer for Belgian National Numbers (Rijksregisternummer / Numero national).

    Format: YY.MM.DD-XXX.CC (11 digits total)
    - YY.MM.DD = date of birth
    - XXX = sequential number (odd for males, even for females)
    - CC = check digits

    Checksum: Modulo 97 validation.
    For persons born before 2000: CC = 97 - (YYMMDDSSS mod 97)
    For persons born in/after 2000: prefix the 9-digit number with '2', then
    CC = 97 - (2YYMMDDSSS mod 97)

    Card view metadata:
      data_categories: [PII]
      data_types: [Government ID]
      regions: [Belgium]
      compliance: [GDPR]
      detection_methods: [Presidio, Content analysis]
    """

    PATTERNS = [
        Pattern(
            "belgium_nn_formatted",
            r"\b\d{2}\.?\d{2}\.?\d{2}[\s\-]?\d{3}\.?\d{2}\b",
            0.5,
        ),
        Pattern(
            "belgium_nn_compact",
            r"\b\d{11}\b",
            0.2,
        ),
    ]

    CONTEXT = [
        "rijksregister",
        "national number",
        "numero national",
        "registre national",
        "nationaal nummer",
        "rijksregisternummer",
    ]

    def __init__(self):
        super().__init__(
            supported_entity="BELGIUM_NATIONAL_NUMBER",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
            supported_language="en",
        )

    def validate_result(self, pattern_text: str) -> bool:
        """Validate using Belgian mod-97 checksum algorithm."""
        # Remove formatting characters
        cleaned = pattern_text.replace(".", "").replace("-", "").replace(" ", "")

        if len(cleaned) != 11:
            return False

        try:
            digits = [int(d) for d in cleaned]
        except ValueError:
            return False

        # Extract parts
        base_9 = int(cleaned[:9])
        check_digits = int(cleaned[9:11])

        # Try pre-2000 calculation first
        expected = 97 - (base_9 % 97)
        if expected == check_digits:
            return True

        # Try post-2000 calculation (prefix with '2')
        base_10 = int("2" + cleaned[:9])
        expected_2000 = 97 - (base_10 % 97)
        if expected_2000 == check_digits:
            return True

        return False

    def invalidate_result(self, pattern_text: str) -> bool:
        """Check for known false positive patterns."""
        cleaned = pattern_text.replace(".", "").replace("-", "").replace(" ", "")
        # All same digits is not a valid number
        if len(set(cleaned)) <= 1:
            return True
        # Check that birth date portion is plausible (MM: 01-12, DD: 01-31)
        try:
            month = int(cleaned[2:4])
            day = int(cleaned[4:6])
            if month < 0 or month > 12 or day < 0 or day > 31:
                return True
        except ValueError:
            return True
        return False
