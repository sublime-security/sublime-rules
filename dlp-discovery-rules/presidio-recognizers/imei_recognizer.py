from presidio_analyzer import PatternRecognizer, Pattern


class ImeiRecognizer(PatternRecognizer):
    """Recognizer for International Mobile Equipment Identity (IMEI) numbers.

    Checksum: Luhn algorithm on 15 digits (last digit is check digit).
    Source: MQL.

    Card view metadata:
        data_categories: [Network Identifiers]
        data_types: [Device Identifier]
        regions: [Global]
        compliance: []
        detection_methods: [Presidio, Content analysis]
    """

    PATTERNS = [
        Pattern("imei_15_digits", r"\b\d{15}\b", 0.4),
        Pattern("imei_formatted", r"\b\d{2}-\d{6}-\d{6}-\d\b", 0.6),
    ]
    CONTEXT = [
        "IMEI",
        "international mobile equipment",
        "device identifier",
        "mobile device",
        "equipment identity",
        "IMEI number",
    ]

    def __init__(self):
        super().__init__(
            supported_entity="IMEI",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
            supported_language="en",
        )

    def validate_result(self, pattern_text: str) -> bool:
        """Validate IMEI using Luhn checksum. Returns True to boost score."""
        digits = [int(d) for d in pattern_text if d.isdigit()]
        if len(digits) != 15:
            return False
        total = 0
        for i, d in enumerate(digits):
            if i % 2 == 1:
                d *= 2
                if d > 9:
                    d -= 9
            total += d
        return total % 10 == 0

    def invalidate_result(self, pattern_text: str) -> bool:
        """Reject clearly invalid IMEIs."""
        digits = [int(d) for d in pattern_text if d.isdigit()]
        if len(digits) != 15:
            return True
        # Reject all-same-digit sequences
        if len(set(digits)) == 1:
            return True
        # TAC (first 8 digits) should not be all zeros
        if all(d == 0 for d in digits[:8]):
            return True
        return False
