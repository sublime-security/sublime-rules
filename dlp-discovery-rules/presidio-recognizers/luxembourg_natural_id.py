from presidio_analyzer import PatternRecognizer, Pattern


class LuxembourgNaturalIdRecognizer(PatternRecognizer):
    """
    Recognizer for Luxembourg National Identification Numbers for natural persons.

    Format: 13 digits (YYYYMMDDXXXCC)
    - YYYYMMDD = date of birth
    - XXX = sequential number
    - CC = check digits (Luhn-based)

    Checksum: Luhn algorithm validation on the full 13-digit number.
    The Luhn algorithm:
    1. Starting from the rightmost digit, double every second digit
    2. If doubling results in a number > 9, subtract 9
    3. Sum all digits
    4. If the total modulo 10 equals 0, the number is valid

    Card view metadata:
      data_categories: [PII]
      data_types: [Government ID]
      regions: [Luxembourg]
      compliance: [GDPR]
      detection_methods: [Presidio, Content analysis]
    """

    PATTERNS = [
        Pattern(
            "luxembourg_natural_id",
            r"\b\d{13}\b",
            0.3,
        ),
        Pattern(
            "luxembourg_natural_id_formatted",
            r"\b\d{4}[\s-]?\d{2}[\s-]?\d{2}[\s-]?\d{3}[\s-]?\d{2}\b",
            0.4,
        ),
    ]

    CONTEXT = [
        "matricule",
        "national identification",
        "numero d'identification",
        "identifiant national",
        "CNS",
        "CCSS",
    ]

    def __init__(self):
        super().__init__(
            supported_entity="LUXEMBOURG_NATURAL_ID",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
            supported_language="en",
        )

    def validate_result(self, pattern_text: str) -> bool:
        """Validate using the Luhn algorithm."""
        cleaned = pattern_text.replace(" ", "").replace("-", "")

        if len(cleaned) != 13:
            return False

        try:
            digits = [int(d) for d in cleaned]
        except ValueError:
            return False

        # Basic date validation (YYYYMMDD)
        year = int(cleaned[:4])
        month = int(cleaned[4:6])
        day = int(cleaned[6:8])

        if year < 1900 or year > 2100:
            return False
        if month < 1 or month > 12:
            return False
        if day < 1 or day > 31:
            return False

        # Luhn algorithm
        total = 0
        for i, digit in enumerate(reversed(digits)):
            if i % 2 == 1:
                doubled = digit * 2
                if doubled > 9:
                    doubled -= 9
                total += doubled
            else:
                total += digit

        return total % 10 == 0

    def invalidate_result(self, pattern_text: str) -> bool:
        """Check for known false positive patterns."""
        cleaned = pattern_text.replace(" ", "").replace("-", "")
        # All same digits is not valid
        if len(set(cleaned)) <= 1:
            return True
        # Sequential digits like 1234567890123 are not valid
        if cleaned == "".join(str(i % 10) for i in range(13)):
            return True
        return False
