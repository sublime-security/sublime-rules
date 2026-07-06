from presidio_analyzer import PatternRecognizer, Pattern


class UsAbaRoutingRecognizer(PatternRecognizer):
    """Recognizer for US ABA Routing Transit Numbers.

    Checksum: weighted sum mod 10. Weights cycle 3, 7, 1 across all 9 digits.
    The weighted sum must be divisible by 10.
    Source: Purview (sit-defn-aba-routing).

    Format: 9 digits. First two digits in ranges 00-12, 21-32, 61-72, or 80.
    Optional hyphens between groups (XXXX-XXXX-X).

    Card view metadata:
        data_categories: [Financial]
        data_types: [Financial Account]
        regions: [United States]
        compliance: [GLBA, SOX]
        detection_methods: [Presidio, Content analysis]
    """

    PATTERNS = [
        Pattern(
            "aba_routing_formatted",
            r"\b\d{4}-?\d{4}-?\d\b",
            0.4,
        ),
        Pattern(
            "aba_routing_unformatted",
            r"\b\d{9}\b",
            0.1,
        ),
    ]
    CONTEXT = [
        "aba",
        "aba number",
        "aba#",
        "abarouting",
        "routing number",
        "routing transit number",
        "routing #",
        "routing no",
        "RTN",
        "bank routing",
        "transit number",
    ]

    # Valid first-two-digit ranges for ABA routing numbers
    _VALID_PREFIXES = set()
    for _lo, _hi in [(0, 12), (21, 32), (61, 72), (80, 80)]:
        for _i in range(_lo, _hi + 1):
            _VALID_PREFIXES.add(_i)

    def __init__(self):
        super().__init__(
            supported_entity="US_ABA_ROUTING_NUMBER",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
            supported_language="en",
        )

    def validate_result(self, pattern_text: str) -> bool:
        """Validate ABA routing number checksum. Returns True to boost score."""
        digits = [int(d) for d in pattern_text if d.isdigit()]
        if len(digits) != 9:
            return False

        # Check valid prefix
        prefix = digits[0] * 10 + digits[1]
        if prefix not in self._VALID_PREFIXES:
            return False

        # Checksum: 3*d1 + 7*d2 + 1*d3 + 3*d4 + 7*d5 + 1*d6 + 3*d7 + 7*d8 + 1*d9 == 0 (mod 10)
        weights = [3, 7, 1, 3, 7, 1, 3, 7, 1]
        total = sum(d * w for d, w in zip(digits, weights))
        return total % 10 == 0

    def invalidate_result(self, pattern_text: str) -> bool:
        """Reject clearly invalid routing numbers."""
        digits = [int(d) for d in pattern_text if d.isdigit()]
        if len(digits) != 9:
            return True
        # Reject all-zero
        if all(d == 0 for d in digits):
            return True
        # Reject all same digit
        if len(set(digits)) == 1:
            return True
        return False
