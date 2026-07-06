from presidio_analyzer import PatternRecognizer, Pattern


class SpainBankAccountRecognizer(PatternRecognizer):
    """
    Recognizer for Spanish Bank Account Numbers (IBAN format).

    Spanish IBAN format: ES + 2 check digits + 20 digits (bank + branch + control + account).
    Validates the IBAN using the standard ISO 13616 mod-97 algorithm:
    1. Move the country code and check digits to the end
    2. Replace letters with numbers (A=10, B=11, ..., Z=35)
    3. Compute mod 97 — result must equal 1

    Checksum: IBAN mod-97 validation (ISO 13616).

    Card view metadata:
      data_categories: [PII]
      data_types: [Financial]
      regions: [Spain]
      compliance: [GDPR]
      detection_methods: [Presidio, Content analysis]
    """

    PATTERNS = [
        Pattern(
            "spain_iban",
            r"\bES\d{2}[\s]?\d{4}[\s]?\d{4}[\s]?\d{4}[\s]?\d{4}[\s]?\d{4}\b",
            0.6,
        ),
        Pattern(
            "spain_iban_compact",
            r"\bES\d{22}\b",
            0.7,
        ),
    ]

    CONTEXT = [
        "IBAN",
        "cuenta bancaria",
        "bank account",
        "banco",
        "transferencia",
        "cuenta corriente",
    ]

    def __init__(self):
        super().__init__(
            supported_entity="SPAIN_BANK_ACCOUNT",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
            supported_language="en",
        )

    def validate_result(self, pattern_text: str) -> bool:
        """Validate using IBAN mod-97 algorithm (ISO 13616)."""
        # Remove spaces and normalize
        cleaned = pattern_text.replace(" ", "").replace("-", "").upper()

        if not cleaned.startswith("ES") or len(cleaned) != 24:
            return False

        try:
            # Move first 4 characters to end
            rearranged = cleaned[4:] + cleaned[:4]

            # Replace letters with numbers (A=10, B=11, ..., Z=35)
            numeric_str = ""
            for char in rearranged:
                if char.isdigit():
                    numeric_str += char
                elif char.isalpha():
                    numeric_str += str(ord(char) - ord("A") + 10)
                else:
                    return False

            # Mod 97 must equal 1
            return int(numeric_str) % 97 == 1
        except (ValueError, IndexError):
            return False

    def invalidate_result(self, pattern_text: str) -> bool:
        """Check for known false positive patterns."""
        cleaned = pattern_text.replace(" ", "")
        # All zeros after country code is not valid
        if cleaned[4:] == "0" * 20:
            return True
        return False
