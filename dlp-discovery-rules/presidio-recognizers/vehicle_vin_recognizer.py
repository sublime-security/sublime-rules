from presidio_analyzer import PatternRecognizer, Pattern


class VehicleVinRecognizer(PatternRecognizer):
    """Recognizer for Vehicle Identification Numbers (VIN).

    Checksum: ISO 3779 transliteration + weighted sum, position 9 is check digit.
    Source: MQL.

    Card view metadata:
        data_categories: [PII]
        data_types: [Device Identifier]
        regions: [Global]
        compliance: []
        detection_methods: [Presidio, Content analysis]
    """

    PATTERNS = [
        Pattern(
            "vin_17_char",
            r"\b[A-HJ-NPR-Z0-9]{17}\b",
            0.5,
        ),
    ]
    CONTEXT = [
        "VIN",
        "vehicle identification",
        "chassis number",
        "vehicle number",
        "frame number",
    ]

    # ISO 3779 transliteration map
    _TRANSLITERATION = {
        "A": 1, "B": 2, "C": 3, "D": 4, "E": 5, "F": 6, "G": 7, "H": 8,
        "J": 1, "K": 2, "L": 3, "M": 4, "N": 5, "P": 7, "R": 9,
        "S": 2, "T": 3, "U": 4, "V": 5, "W": 6, "X": 7, "Y": 8, "Z": 9,
    }

    # Positional weights for positions 1-17
    _WEIGHTS = [8, 7, 6, 5, 4, 3, 2, 10, 0, 9, 8, 7, 6, 5, 4, 3, 2]

    def __init__(self):
        super().__init__(
            supported_entity="VEHICLE_VIN",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
            supported_language="en",
        )

    def _transliterate(self, char: str) -> int:
        """Convert a VIN character to its numeric value."""
        if char.isdigit():
            return int(char)
        return self._TRANSLITERATION.get(char.upper(), 0)

    def validate_result(self, pattern_text: str) -> bool:
        """Validate VIN check digit (position 9). Returns True to boost score."""
        vin = pattern_text.upper().strip()
        if len(vin) != 17:
            return False

        total = sum(
            self._transliterate(c) * w for c, w in zip(vin, self._WEIGHTS)
        )
        remainder = total % 11
        expected = "X" if remainder == 10 else str(remainder)
        return vin[8] == expected

    def invalidate_result(self, pattern_text: str) -> bool:
        """Reject clearly invalid VINs."""
        vin = pattern_text.upper().strip()
        if len(vin) != 17:
            return True
        # Reject if all same character
        if len(set(vin)) == 1:
            return True
        # I, O, Q are never valid in VINs
        if any(c in vin for c in "IOQ"):
            return True
        return False
