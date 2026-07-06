from presidio_analyzer import PatternRecognizer, Pattern


class UsDeaNumberRecognizer(PatternRecognizer):
    """Recognizer for US Drug Enforcement Administration (DEA) registration numbers.

    Checksum: Sum of digits at odd positions + 2 * sum of digits at even positions.
    Last digit of total must equal the 7th digit (check digit).
    Source: Purview (sit-defn-drug-enforcement-agency-number).

    Format: 2 letters + 7 digits.
    - First letter: registrant type code (A, B, F, G, M, P, R)
    - Second letter: first letter of registrant last name, or '9'
    - 7 digits, last is check digit

    Card view metadata:
        data_categories: [PII, PHI]
        data_types: [Healthcare ID]
        regions: [United States]
        compliance: [HIPAA]
        detection_methods: [Presidio, Content analysis]
    """

    PATTERNS = [
        Pattern(
            "dea_number",
            r"\b[ABFGMPRabfgmpr][A-Za-z9]\d{7}\b",
            0.65,
        ),
    ]
    CONTEXT = [
        "DEA",
        "dea#",
        "dea number",
        "drug enforcement",
        "drug enforcement administration",
        "drug enforcement agency",
        "DEA registration",
        "controlled substance",
    ]

    def __init__(self):
        super().__init__(
            supported_entity="US_DEA_NUMBER",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
            supported_language="en",
        )

    def validate_result(self, pattern_text: str) -> bool:
        """Validate DEA number check digit. Returns True to boost score."""
        text = pattern_text.strip()
        if len(text) != 9:
            return False

        # First char must be a valid registrant code
        if text[0].upper() not in "ABFGMPR":
            return False

        # Second char must be a letter or '9'
        if not (text[1].isalpha() or text[1] == "9"):
            return False

        digits = []
        for c in text[2:]:
            if not c.isdigit():
                return False
            digits.append(int(c))

        if len(digits) != 7:
            return False

        # Checksum: sum of odd-position digits + 2 * sum of even-position digits
        # Positions are 1-indexed within the 7-digit portion
        odd_sum = digits[0] + digits[2] + digits[4]
        even_sum = digits[1] + digits[3] + digits[5]
        total = odd_sum + 2 * even_sum
        return total % 10 == digits[6]

    def invalidate_result(self, pattern_text: str) -> bool:
        """Reject clearly invalid DEA numbers."""
        text = pattern_text.strip()
        if len(text) != 9:
            return True
        # All digits portion should not be all zeros
        digit_part = text[2:]
        if all(c == "0" for c in digit_part):
            return True
        return False
