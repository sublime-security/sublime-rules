# DLP Presidio Recognizer Coverage

> Auto-generated tracking table of all Presidio recognizers and MQL DLP rules.
> **254 total entries** across 33 region/category sections.
> Custom recognizers: **213** | Built-in (Presidio): **41**

---

## 1. United States

| # | Entity Name | Entity Type Key | Source | Presidio Built-in? | Recognizer Route | File | Checksum | data_categories | data_types | regions | compliance | Status |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 | Recognizer for US ABA Routing Transit Numbers | `US_ABA_ROUTING_NUMBER` | Purview | No | Python | `us_aba_routing_recognizer.py` | None | Financial | Financial Account | United States | GLBA, SOX | Done |
| 2 | US Bank Account Number | `US_BANK_NUMBER` | MQL | Yes | — | `— (built-in: `UsBankRecognizer`)` | — | Financial | Financial Account | United States | GLBA, SOX | Done (built-in) |
| 3 | US Driver's License Number | `US_DRIVER_LICENSE` | MQL | Yes | — | `— (built-in: `UsLicenseRecognizer`)` | — | PII | Government ID | United States | CCPA, GLBA | Done (built-in) |
| 4 | US Individual Taxpayer Identification Number (ITIN) | `US_ITIN` | MQL | Yes | — | `— (built-in: `UsItinRecognizer`)` | — | PII | Government ID | United States | CCPA, GLBA | Done (built-in) |
| 5 | US Passport Number | `US_PASSPORT` | MQL | Yes | — | `— (built-in: `UsPassportRecognizer`)` | — | PII | Government ID | United States | CCPA, GLBA | Done (built-in) |
| 6 | US Physical Address | `US_PHYSICAL_ADDRESS` | Purview | No | YAML | `us_physical_address_recognizer.yml` | None | PII | Physical Address | United States | CCPA, GLBA | Done |
| 7 | US Social Security Number (SSN) | `US_SSN` | MQL | Yes | — | `— (built-in: `UsSsnRecognizer`)` | — | PII | Government ID | United States | CCPA, GLBA | Done (built-in) |

## 2. Canada

| # | Entity Name | Entity Type Key | Source | Presidio Built-in? | Recognizer Route | File | Checksum | data_categories | data_types | regions | compliance | Status |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 8 | Canada Bank Account Number | `CA_BANK_ACCOUNT` | MQL | No | YAML | `ca_bank_account_recognizer.yml` | None | Financial | Financial Account | Canada | — | Done |
| 9 | Canada Driver's License Number | `CA_DRIVERS_LICENSE` | MQL | No | YAML | `ca_drivers_license_recognizer.yml` | None | PII | Government ID | Canada | — | Done |
| 10 | Canada Passport Number | `CA_PASSPORT` | MQL | No | YAML | `ca_passport_recognizer.yml` | None | PII | Government ID | Canada | — | Done |
| 11 | Canada Social Insurance Number (SIN) | `CA_SIN` | MQL | Yes | — | `— (built-in: `CaSinRecognizer`)` | — | PII | Government ID | Canada | — | Done (built-in) |

## 3. United Kingdom

| # | Entity Name | Entity Type Key | Source | Presidio Built-in? | Recognizer Route | File | Checksum | data_categories | data_types | regions | compliance | Status |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 12 | UK Driver's License | `UK_DRIVERS_LICENSE` | Purview | No | YAML | `uk_drivers_license.yml` | None | PII | Government ID | United Kingdom | GDPR | Done |
| 13 | UK Electoral Roll | `UK_ELECTORAL_ROLL` | Purview | No | YAML | `uk_electoral_roll.yml` | None | PII | Government ID | United Kingdom | GDPR | Done |
| 14 | UK National Health Service Number | `NHS_NUMBER` | MQL | Yes | — | `— (built-in: `NhsRecognizer`)` | — | PII | Healthcare | United Kingdom | GDPR | Done (built-in) |
| 15 | UK National Insurance Number (NINO) | `UK_NINO` | MQL | Yes | — | `— (built-in: `UkNinoRecognizer`)` | — | PII | Government ID | United Kingdom | GDPR | Done (built-in) |
| 16 | UK Passport Number | `UK_PASSPORT` | MQL | Yes | — | `— (built-in: `UkPassportRecognizer`)` | — | PII | Government ID | United Kingdom | GDPR | Done (built-in) |
| 17 | UK SWIFT Code | `UK_SWIFT_CODE` | MQL | No | YAML | `uk_swift_code.yml` | None | PII | Financial | United Kingdom | GDPR | Done |
| 18 | UK Unique Taxpayer Reference | `UK_UTR` | Purview | No | YAML | `uk_utr.yml` | None | PII | Tax | United Kingdom | GDPR | Done |

## 4. Germany

| # | Entity Name | Entity Type Key | Source | Presidio Built-in? | Recognizer Route | File | Checksum | data_categories | data_types | regions | compliance | Status |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 19 | Germany Bank Account Number (IBAN) | `IBAN` | MQL | Yes | — | `— (built-in: `IbanRecognizer`)` | — | PII | Financial | Germany | GDPR | Done (built-in) |
| 20 | Germany Driver's License Number | `DE_DRIVERS_LICENSE` | MQL | Yes | — | `— (built-in: `DeDriversLicenseRecognizer`)` | — | PII | Government ID | Germany | GDPR | Done (built-in) |
| 21 | Germany Identity Card Number (Personalausweisnummer) | `DE_IDENTITY_CARD` | MQL | Yes | — | `— (built-in: `DeIdentityCardRecognizer`)` | — | PII | Government ID | Germany | GDPR | Done (built-in) |
| 22 | Germany Passport Number | `DE_PASSPORT` | MQL | Yes | — | `— (built-in: `DePassportRecognizer`)` | — | PII | Government ID | Germany | GDPR | Done (built-in) |
| 23 | Germany Tax Identification Number | `DE_TAX_ID` | MQL | Yes | — | `— (built-in: `DeTaxIdRecognizer`)` | — | PII | Tax | Germany | GDPR | Done (built-in) |
| 24 | Germany VAT Number | `DE_VAT` | Purview | No | YAML | `de_vat.yml` | None | PII | Tax | Germany | GDPR | Done |

## 5. France

| # | Entity Name | Entity Type Key | Source | Presidio Built-in? | Recognizer Route | File | Checksum | data_categories | data_types | regions | compliance | Status |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 25 | France Bank Account | `FRANCE_BANK_ACCOUNT` | MQL | No | YAML | `france_bank_account.yml` | None | PII | Financial | France | GDPR | Done |
| 26 | France CNI | `FRANCE_CNI` | MQL | No | YAML | `france_cni.yml` | None | PII | Government ID | France | GDPR | Done |
| 27 | France Driver's License | `FRANCE_DRIVERS_LICENSE` | MQL | No | YAML | `france_drivers_license.yml` | None | PII | Government ID | France | GDPR | Done |
| 28 | France Passport | `FRANCE_PASSPORT` | MQL | No | YAML | `france_passport.yml` | None | PII | Government ID | France | GDPR | Done |
| 29 | France Tax ID | `FRANCE_TAX_ID` | MQL | No | YAML | `france_tax_id.yml` | None | PII | Tax | France | GDPR | Done |
| 30 | France VAT Number | `FRANCE_VAT` | Purview | No | YAML | `france_vat.yml` | None | PII | Tax | France | GDPR | Done |
| 31 | Recognizer for French Social Security Numbers (INSEE/NIR) | `FRANCE_INSEE` | MQL | No | Python | `france_insee.py` | None | PII | Government ID | France | GDPR | Done |

## 6. Spain

| # | Entity Name | Entity Type Key | Source | Presidio Built-in? | Recognizer Route | File | Checksum | data_categories | data_types | regions | compliance | Status |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 32 | Recognizer for Spanish Bank Account Numbers (IBAN format) | `SPAIN_BANK_ACCOUNT` | MQL | No | Python | `spain_bank_account.py` | None | PII | Financial | Spain | GDPR | Done |
| 33 | Spain DNI/NIE | `ES_NIF` | MQL | Yes | — | `— (built-in: `EsNifRecognizer`)` | — | PII | Government ID | Spain | GDPR | Done (built-in) |
| 34 | Spain Driver's License | `SPAIN_DRIVERS_LICENSE` | Purview | No | YAML | `spain_drivers_license.yml` | None | PII | Government ID | Spain | GDPR | Done |
| 35 | Spain Passport Number | `ES_PASSPORT` | MQL | Yes | — | `— (built-in: `EsPassportRecognizer`)` | — | PII | Government ID | Spain | GDPR | Done (built-in) |
| 36 | Spain Social Security Number | `SPAIN_SSN` | MQL | No | YAML | `spain_ssn.yml` | None | PII | Government ID | Spain | GDPR | Done |
| 37 | Spain Tax ID | `SPAIN_TAX_ID` | MQL | No | YAML | `spain_tax_id.yml` | None | PII | Tax | Spain | GDPR | Done |

## 7. Italy

| # | Entity Name | Entity Type Key | Source | Presidio Built-in? | Recognizer Route | File | Checksum | data_categories | data_types | regions | compliance | Status |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 38 | Italy Driver's License | `IT_DRIVERS_LICENSE` | Purview | No | YAML | `it_drivers_license.yml` | None | PII | Government ID | Italy | GDPR | Done |
| 39 | Italy Fiscal Code | `IT_FISCAL_CODE` | MQL | Yes | — | `— (built-in: `ItFiscalCodeRecognizer`)` | — | PII | Government ID | Italy | GDPR | Done (built-in) |
| 40 | Italy Passport | `IT_PASSPORT` | Purview | No | YAML | `it_passport.yml` | None | PII | Government ID | Italy | GDPR | Done |
| 41 | Italy VAT Number | `IT_VAT` | Purview | No | YAML | `it_vat.yml` | None | PII | Tax | Italy | GDPR | Done |

## 8. Portugal

| # | Entity Name | Entity Type Key | Source | Presidio Built-in? | Recognizer Route | File | Checksum | data_categories | data_types | regions | compliance | Status |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 42 | Portugal Citizen Card | `PORTUGAL_CITIZEN_CARD` | MQL | No | YAML | `portugal_citizen_card.yml` | None | PII | Government ID | Portugal | GDPR | Done |
| 43 | Portugal Driver's License | `PORTUGAL_DRIVERS_LICENSE` | Purview | No | YAML | `portugal_drivers_license.yml` | None | PII | Government ID | Portugal | GDPR | Done |
| 44 | Portugal Passport | `PORTUGAL_PASSPORT` | Purview | No | YAML | `portugal_passport.yml` | None | PII | Government ID | Portugal | GDPR | Done |
| 45 | Recognizer for Portuguese Tax Identification Numbers (NIF) | `PORTUGAL_TAX_ID` | MQL | No | Python | `portugal_tax_id.py` | None | PII | Tax | Portugal | GDPR | Done |

## 9. Belgium

| # | Entity Name | Entity Type Key | Source | Presidio Built-in? | Recognizer Route | File | Checksum | data_categories | data_types | regions | compliance | Status |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 46 | Belgium Driver's License | `BELGIUM_DRIVERS_LICENSE` | Purview | No | YAML | `belgium_drivers_license.yml` | None | PII | Government ID | Belgium | GDPR | Done |
| 47 | Belgium Passport | `BELGIUM_PASSPORT` | Purview | No | YAML | `belgium_passport.yml` | None | PII | Government ID | Belgium | GDPR | Done |
| 48 | Belgium VAT Number | `BELGIUM_VAT` | Purview | No | YAML | `belgium_vat.yml` | None | PII | Tax | Belgium | GDPR | Done |
| 49 | Recognizer for Belgian National Numbers (Rijksregisternummer / Numero national) | `BELGIUM_NATIONAL_NUMBER` | MQL | No | Python | `belgium_national_number.py` | None | PII | Government ID | Belgium | GDPR | Done |

## 10. Netherlands

| # | Entity Name | Entity Type Key | Source | Presidio Built-in? | Recognizer Route | File | Checksum | data_categories | data_types | regions | compliance | Status |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 50 | Netherlands Driver's License | `NETHERLANDS_DRIVERS_LICENSE` | Purview | No | YAML | `netherlands_drivers_license.yml` | None | PII | Government ID | Netherlands | GDPR | Done |
| 51 | Netherlands Passport | `NETHERLANDS_PASSPORT` | Purview | No | YAML | `netherlands_passport.yml` | None | PII | Government ID | Netherlands | GDPR | Done |
| 52 | Netherlands Tax ID | `NETHERLANDS_TAX_ID` | MQL | No | YAML | `netherlands_tax_id.yml` | None | PII | Tax | Netherlands | GDPR | Done |
| 53 | Netherlands VAT Number | `NETHERLANDS_VAT` | Purview | No | YAML | `netherlands_vat.yml` | None | PII | Tax | Netherlands | GDPR | Done |
| 54 | Recognizer for Dutch Citizen's Service Numbers (Burgerservicenummer / BSN) | `NETHERLANDS_BSN` | MQL | No | Python | `netherlands_bsn.py` | None | PII | Government ID | Netherlands | GDPR | Done |

## 11. Luxembourg

| # | Entity Name | Entity Type Key | Source | Presidio Built-in? | Recognizer Route | File | Checksum | data_categories | data_types | regions | compliance | Status |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 55 | Luxembourg Driver's License | `LU_DRIVERS_LICENSE` | Purview | No | YAML | `lu_drivers_license.yml` | None | PII | Government ID | Luxembourg | GDPR | Done |
| 56 | Luxembourg Non-Natural ID | `LUXEMBOURG_NONNATURAL_ID` | MQL | No | YAML | `luxembourg_nonnatural_id.yml` | None | PII | Government ID | Luxembourg | GDPR | Done |
| 57 | Luxembourg Passport | `LU_PASSPORT` | Purview | No | YAML | `lu_passport.yml` | None | PII | Government ID | Luxembourg | GDPR | Done |
| 58 | Recognizer for Luxembourg National Identification Numbers for natural persons | `LUXEMBOURG_NATURAL_ID` | MQL | No | Python | `luxembourg_natural_id.py` | None | PII | Government ID | Luxembourg | GDPR | Done |

## 12. Nordic (Sweden, Denmark, Finland)

| # | Entity Name | Entity Type Key | Source | Presidio Built-in? | Recognizer Route | File | Checksum | data_categories | data_types | regions | compliance | Status |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 59 | Denmark Driver's License Number | `DK_DRIVERS_LICENSE` | Purview | No | YAML | `dk_drivers_license_recognizer.yml` | None | PII | Driver's License | Denmark | GDPR | Done |
| 60 | Denmark Passport Number | `DK_PASSPORT` | Purview | No | YAML | `dk_passport_recognizer.yml` | None | PII | Passport | Denmark | GDPR | Done |
| 61 | Denmark Personal Identification Number (CPR-nummer) Recognizer | `DK_PERSONAL_ID` | MQL | No | Python | `dk_personal_id_recognizer.py` | None | PII | Government ID | Denmark | GDPR | Done |
| 62 | Finland Driver's License Number | `FI_DRIVERS_LICENSE` | Purview | No | YAML | `fi_drivers_license_recognizer.yml` | None | PII | Driver's License | Finland | GDPR | Done |
| 63 | Finland National ID | `FI_PERSONAL_IDENTITY_CODE` | MQL | Yes | — | `— (built-in: `FiPersonalIdentityCodeRecognizer`)` | — | PII | Government ID | Finland | GDPR | Done (built-in) |
| 64 | Finland Passport Number | `FI_PASSPORT` | Purview | No | YAML | `fi_passport_recognizer.yml` | None | PII | Passport | Finland | GDPR | Done |
| 65 | Sweden Driver's License Number | `SE_DRIVERS_LICENSE` | Purview | No | YAML | `se_drivers_license_recognizer.yml` | None | PII | Driver's License | Sweden | GDPR | Done |
| 66 | Sweden National ID | `SE_PERSONAL_NUMBER` | MQL | Yes | — | `— (built-in: `SePersonalNumberRecognizer`)` | — | PII | Government ID | Sweden | GDPR | Done (built-in) |
| 67 | Sweden Passport Number | `SE_PASSPORT` | Purview | No | YAML | `se_passport_recognizer.yml` | None | PII | Passport | Sweden | GDPR | Done |
| 68 | Sweden Tax Identification Number | `SE_TAX_ID` | MQL + Purview | No | YAML | `se_tax_id_recognizer.yml` | None | PII | Tax ID | Sweden | GDPR | Done |

## 13. Baltic (Estonia, Latvia, Lithuania)

| # | Entity Name | Entity Type Key | Source | Presidio Built-in? | Recognizer Route | File | Checksum | data_categories | data_types | regions | compliance | Status |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 69 | Estonia Driver's License Number | `EE_DRIVERS_LICENSE` | Purview | No | YAML | `ee_drivers_license_recognizer.yml` | None | PII | Driver's License | Estonia | GDPR | Done |
| 70 | Estonia Passport Number | `EE_PASSPORT` | Purview | No | YAML | `ee_passport_recognizer.yml` | None | PII | Passport | Estonia | GDPR | Done |
| 71 | Estonia Personal Identification Code (Isikukood) Recognizer | `EE_PERSONAL_CODE` | MQL | No | Python | `ee_personal_code_recognizer.py` | None | PII | Government ID | Estonia | GDPR | Done |
| 72 | Latvia Driver's License Number | `LV_DRIVERS_LICENSE` | Purview | No | YAML | `lv_drivers_license_recognizer.yml` | None | PII | Driver's License | Latvia | GDPR | Done |
| 73 | Latvia Passport Number | `LV_PASSPORT` | Purview | No | YAML | `lv_passport_recognizer.yml` | None | PII | Passport | Latvia | GDPR | Done |
| 74 | Latvia Personal Code (Personas kods) Recognizer | `LV_PERSONAL_CODE` | MQL | No | Python | `lv_personal_code_recognizer.py` | None | PII | Government ID | Latvia | GDPR | Done |
| 75 | Lithuania Driver's License Number | `LT_DRIVERS_LICENSE` | Purview | No | YAML | `lt_drivers_license_recognizer.yml` | None | PII | Driver's License | Lithuania | GDPR | Done |
| 76 | Lithuania Passport Number | `LT_PASSPORT` | Purview | No | YAML | `lt_passport_recognizer.yml` | None | PII | Passport | Lithuania | GDPR | Done |
| 77 | Lithuania Personal Code (Asmens kodas) Recognizer | `LT_PERSONAL_CODE` | MQL | No | Python | `lt_personal_code_recognizer.py` | None | PII | Government ID | Lithuania | GDPR | Done |

## 14. Central Europe (Austria, Poland, Czech, Slovakia, Hungary)

| # | Entity Name | Entity Type Key | Source | Presidio Built-in? | Recognizer Route | File | Checksum | data_categories | data_types | regions | compliance | Status |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 78 | Austria Driver's License Number | `AT_DRIVERS_LICENSE` | Purview | No | YAML | `at_drivers_license_recognizer.yml` | None | PII | Driver's License | Austria | GDPR | Done |
| 79 | Austria Identity Card Number | `AT_IDENTITY_CARD` | MQL + Purview | No | YAML | `at_identity_card_recognizer.yml` | None | PII | Government ID | Austria | GDPR | Done |
| 80 | Austria Passport Number | `AT_PASSPORT` | Purview | No | YAML | `at_passport_recognizer.yml` | None | PII | Passport | Austria | GDPR | Done |
| 81 | Austria Social Security Number | `AT_SOCIAL_SECURITY` | MQL + Purview | No | YAML | `at_social_security_recognizer.yml` | None | PII | Social Security Number | Austria | GDPR | Done |
| 82 | Austria Tax Identification Number | `AT_TAX_ID` | MQL + Purview | No | YAML | `at_tax_id_recognizer.yml` | None | PII | Tax ID | Austria | GDPR | Done |
| 83 | Austria VAT Number | `AT_VAT` | Purview | No | YAML | `at_vat_recognizer.yml` | None | PII | Tax ID | Austria | GDPR | Done |
| 84 | Czech Personal Identity Number (Rodne cislo) Recognizer | `CZ_PERSONAL_ID` | MQL | No | Python | `cz_personal_id_recognizer.py` | None | PII | Government ID | Czech Republic | GDPR | Done |
| 85 | Czech Republic Driver's License Number | `CZ_DRIVERS_LICENSE` | Purview | No | YAML | `cz_drivers_license_recognizer.yml` | None | PII | Driver's License | Czech Republic | GDPR | Done |
| 86 | Czech Republic Passport Number | `CZ_PASSPORT` | Purview | No | YAML | `cz_passport_recognizer.yml` | None | PII | Passport | Czech Republic | GDPR | Done |
| 87 | Hungary Driver's License Number | `HU_DRIVERS_LICENSE` | Purview | No | YAML | `hu_drivers_license_recognizer.yml` | None | PII | Driver's License | Hungary | GDPR | Done |
| 88 | Hungary Passport Number | `HU_PASSPORT` | Purview | No | YAML | `hu_passport_recognizer.yml` | None | PII | Passport | Hungary | GDPR | Done |
| 89 | Hungary Personal Identification Number | `HU_PERSONAL_ID` | MQL + Purview | No | YAML | `hu_personal_id_recognizer.yml` | None | PII | Government ID | Hungary | GDPR | Done |
| 90 | Hungary Social Security Number (TAJ) Recognizer | `HU_TAJ` | MQL | No | Python | `hu_taj_recognizer.py` | None | PII | Social Security Number | Hungary | GDPR | Done |
| 91 | Hungary Tax Identification Number Recognizer | `HU_TAX_ID` | MQL | No | Python | `hu_tax_id_recognizer.py` | None | PII | Tax ID | Hungary | GDPR | Done |
| 92 | Hungary VAT Number | `HU_VAT` | Purview | No | YAML | `hu_vat_recognizer.yml` | None | PII | Tax ID | Hungary | GDPR | Done |
| 93 | Poland Driver's License Number | `PL_DRIVERS_LICENSE` | Purview | No | YAML | `pl_drivers_license_recognizer.yml` | None | PII | Driver's License | Poland | GDPR | Done |
| 94 | Poland Identity Card Number | `PL_IDENTITY_CARD` | MQL + Purview | No | YAML | `pl_identity_card_recognizer.yml` | None | PII | Government ID | Poland | GDPR | Done |
| 95 | Poland PESEL Number Recognizer | `PL_PESEL` | MQL | No | Python | `pl_pesel_recognizer.py` | None | PII | Government ID | Poland | GDPR | Done |
| 96 | Poland Passport Number | `PL_PASSPORT` | Purview | No | YAML | `pl_passport_recognizer.yml` | None | PII | Passport | Poland | GDPR | Done |
| 97 | Poland REGON Number Recognizer | `PL_REGON` | MQL | No | Python | `pl_regon_recognizer.py` | None | PII | Business Registration | Poland | GDPR | Done |
| 98 | Poland Tax Identification Number (NIP) | `PL_TAX_ID` | MQL + Purview | No | YAML | `pl_tax_id_recognizer.yml` | None | PII | Tax ID | Poland | GDPR | Done |
| 99 | Slovakia Driver's License Number | `SK_DRIVERS_LICENSE` | Purview | No | YAML | `sk_drivers_license_recognizer.yml` | None | PII | Driver's License | Slovakia | GDPR | Done |
| 100 | Slovakia Passport Number | `SK_PASSPORT` | Purview | No | YAML | `sk_passport_recognizer.yml` | None | PII | Passport | Slovakia | GDPR | Done |
| 101 | Slovakia Personal Number (Rodne cislo) Recognizer | `SK_PERSONAL_NUMBER` | MQL | No | Python | `sk_personal_number_recognizer.py` | None | PII | Government ID | Slovakia | GDPR | Done |

## 15. Southeast Europe (Romania, Bulgaria, Croatia, Slovenia)

| # | Entity Name | Entity Type Key | Source | Presidio Built-in? | Recognizer Route | File | Checksum | data_categories | data_types | regions | compliance | Status |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 102 | Bulgaria Driver's License Number | `BG_DRIVERS_LICENSE` | Purview | No | YAML | `bg_drivers_license_recognizer.yml` | None | PII | Driver's License | Bulgaria | GDPR | Done |
| 103 | Bulgaria Passport Number | `BG_PASSPORT` | Purview | No | YAML | `bg_passport_recognizer.yml` | None | PII | Passport | Bulgaria | GDPR | Done |
| 104 | Bulgaria Uniform Civil Number (EGN) Recognizer | `BG_UCN` | MQL | No | Python | `bg_ucn_recognizer.py` | None | PII | Government ID | Bulgaria | GDPR | Done |
| 105 | Croatia Driver's License Number | `HR_DRIVERS_LICENSE` | Purview | No | YAML | `hr_drivers_license_recognizer.yml` | None | PII | Driver's License | Croatia | GDPR | Done |
| 106 | Croatia Identity Card Number | `HR_IDENTITY_CARD` | Purview | No | YAML | `hr_identity_card_recognizer.yml` | None | PII | Government ID | Croatia | GDPR | Done |
| 107 | Croatia Passport Number | `HR_PASSPORT` | Purview | No | YAML | `hr_passport_recognizer.yml` | None | PII | Passport | Croatia | GDPR | Done |
| 108 | Croatia Personal Identification Number (OIB) Recognizer | `HR_OIB` | MQL | No | Python | `hr_oib_recognizer.py` | None | PII | Government ID | Croatia | GDPR | Done |
| 109 | Romania Driver's License Number | `RO_DRIVERS_LICENSE` | Purview | No | YAML | `ro_drivers_license_recognizer.yml` | None | PII | Driver's License | Romania | GDPR | Done |
| 110 | Romania Passport Number | `RO_PASSPORT` | Purview | No | YAML | `ro_passport_recognizer.yml` | None | PII | Passport | Romania | GDPR | Done |
| 111 | Romania Personal Numerical Code (CNP) Recognizer | `RO_PERSONAL_CODE` | MQL | No | Python | `ro_personal_code_recognizer.py` | None | PII | Government ID | Romania | GDPR | Done |
| 112 | Slovenia Driver's License Number | `SI_DRIVERS_LICENSE` | Purview | No | YAML | `si_drivers_license_recognizer.yml` | None | PII | Driver's License | Slovenia | GDPR | Done |
| 113 | Slovenia Passport Number | `SI_PASSPORT` | Purview | No | YAML | `si_passport_recognizer.yml` | None | PII | Passport | Slovenia | GDPR | Done |
| 114 | Slovenia Tax Identification Number | `SI_TAX_ID` | MQL + Purview | No | YAML | `si_tax_id_recognizer.yml` | None | PII | Tax ID | Slovenia | GDPR | Done |
| 115 | Slovenia Unique Master Citizen Number (EMSO) Recognizer | `SI_EMSO` | MQL | No | Python | `si_emso_recognizer.py` | None | PII | Government ID | Slovenia | GDPR | Done |

## 16. Mediterranean (Greece, Cyprus, Malta, Ireland, Turkey)

| # | Entity Name | Entity Type Key | Source | Presidio Built-in? | Recognizer Route | File | Checksum | data_categories | data_types | regions | compliance | Status |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 116 | Cyprus Driver's License Number | `CY_DRIVERS_LICENSE` | Purview | No | YAML | `cy_drivers_license_recognizer.yml` | None | PII | Driver's License | Cyprus | GDPR | Done |
| 117 | Cyprus Identity Card Number | `CY_IDENTITY_CARD` | MQL + Purview | No | YAML | `cy_identity_card_recognizer.yml` | None | PII | Government ID | Cyprus | GDPR | Done |
| 118 | Cyprus Passport Number | `CY_PASSPORT` | Purview | No | YAML | `cy_passport_recognizer.yml` | None | PII | Passport | Cyprus | GDPR | Done |
| 119 | Cyprus Tax Identification Number | `CY_TAX_ID` | Purview | No | YAML | `cy_tax_id_recognizer.yml` | None | PII | Tax ID | Cyprus | GDPR | Done |
| 120 | Greece Driver's License Number | `GR_DRIVERS_LICENSE` | Purview | No | YAML | `gr_drivers_license_recognizer.yml` | None | PII | Driver's License | Greece | GDPR | Done |
| 121 | Greece National ID Card Number | `GR_NATIONAL_ID` | MQL + Purview | No | YAML | `gr_national_id_recognizer.yml` | None | PII | Government ID | Greece | GDPR | Done |
| 122 | Greece Passport Number | `GR_PASSPORT` | Purview | No | YAML | `gr_passport_recognizer.yml` | None | PII | Passport | Greece | GDPR | Done |
| 123 | Greece Social Security Number (AMKA) Recognizer | `GR_AMKA` | MQL | No | Python | `gr_amka_recognizer.py` | None | PII | Social Security Number | Greece | GDPR | Done |
| 124 | Greece Tax Identification Number (AFM) Recognizer | `GR_TAX_ID` | MQL | No | Python | `gr_tax_id_recognizer.py` | None | PII | Tax ID | Greece | GDPR | Done |
| 125 | Ireland Driver's License Number | `IE_DRIVERS_LICENSE` | Purview | No | YAML | `ie_drivers_license_recognizer.yml` | None | PII | Driver's License | Ireland | GDPR | Done |
| 126 | Ireland Passport Number | `IE_PASSPORT` | Purview | No | YAML | `ie_passport_recognizer.yml` | None | PII | Passport | Ireland | GDPR | Done |
| 127 | Ireland Personal Public Service (PPS) Number Recognizer | `IE_PPS` | MQL | No | Python | `ie_pps_recognizer.py` | None | PII | Government ID | Ireland | GDPR | Done |
| 128 | Malta Driver's License Number | `MT_DRIVERS_LICENSE` | Purview | No | YAML | `mt_drivers_license_recognizer.yml` | None | PII | Driver's License | Malta | GDPR | Done |
| 129 | Malta Identity Card Number | `MT_IDENTITY_CARD` | MQL + Purview | No | YAML | `mt_identity_card_recognizer.yml` | None | PII | Government ID | Malta | GDPR | Done |
| 130 | Malta Passport Number | `MT_PASSPORT` | Purview | No | YAML | `mt_passport_recognizer.yml` | None | PII | Passport | Malta | GDPR | Done |
| 131 | Malta Tax ID Number | `MT_TAX_ID` | MQL + Purview | No | YAML | `mt_tax_id_recognizer.yml` | None | PII | Tax ID | Malta | GDPR | Done |
| 132 | Turkey ID Number | `TR_NATIONAL_ID` | MQL | Yes | — | `— (built-in: `TrNationalIdRecognizer`)` | — | PII | Government ID | Turkey | GDPR | Done (built-in) |

## 17. Other European (Norway, Russia, Ukraine, Switzerland)

| # | Entity Name | Entity Type Key | Source | Presidio Built-in? | Recognizer Route | File | Checksum | data_categories | data_types | regions | compliance | Status |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 133 | Norway Identification Number (Fodselsnummer) Recognizer | `NO_IDENTIFICATION_NUMBER` | MQL | No | Python | `no_identification_number_recognizer.py` | None | PII | Government ID | Norway | GDPR | Done |
| 134 | Russia Domestic Passport Number | `RU_DOMESTIC_PASSPORT` | Purview | No | YAML | `ru_domestic_passport_recognizer.yml` | None | PII | Passport | Russia | — | Done |
| 135 | Russia International Passport Number | `RU_INTERNATIONAL_PASSPORT` | Purview | No | YAML | `ru_international_passport_recognizer.yml` | None | PII | Passport | Russia | — | Done |
| 136 | Switzerland Social Security Number (AHV/AVS) Recognizer | `CH_AHV` | MQL | No | Python | `ch_ahv_recognizer.py` | None | PII | Social Security Number | Switzerland | GDPR | Done |
| 137 | Ukraine Domestic Passport Number | `UA_DOMESTIC_PASSPORT` | Purview | No | YAML | `ua_domestic_passport_recognizer.yml` | None | PII | Passport | Ukraine | — | Done |
| 138 | Ukraine International Passport Number | `UA_INTERNATIONAL_PASSPORT` | Purview | No | YAML | `ua_international_passport_recognizer.yml` | None | PII | Passport | Ukraine | — | Done |

## 19. India

| # | Entity Name | Entity Type Key | Source | Presidio Built-in? | Recognizer Route | File | Checksum | data_categories | data_types | regions | compliance | Status |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 139 | India Aadhaar Number | `IN_AADHAAR` | MQL | Yes | — | `— (built-in: `InAadhaarRecognizer`)` | — | PII | Government ID | India | — | Done (built-in) |
| 140 | India IFSC Code | `IN_BANK_ACCOUNT` | MQL | No | YAML | `in_bank_account_recognizer.yml` | None | Financial | Financial Account | India | — | Done |
| 141 | India PAN Number | `IN_PAN` | MQL | Yes | — | `— (built-in: `InPanRecognizer`)` | — | Financial | Tax ID | India | — | Done (built-in) |
| 142 | India Passport Number | `IN_PASSPORT` | MQL | Yes | — | `— (built-in: `InPassportRecognizer`)` | — | PII | Government ID | India | — | Done (built-in) |

## 20. Japan

| # | Entity Name | Entity Type Key | Source | Presidio Built-in? | Recognizer Route | File | Checksum | data_categories | data_types | regions | compliance | Status |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 143 | Japan Bank Account Number | `JP_BANK_ACCOUNT` | MQL | No | YAML | `jp_bank_account_recognizer.yml` | None | Financial | Financial Account | Japan | — | Done |
| 144 | Japan Driver's License Number | `JP_DRIVERS_LICENSE` | MQL | No | YAML | `jp_drivers_license_recognizer.yml` | None | PII | Government ID | Japan | — | Done |
| 145 | Japan MyNumber Recognizer | `JP_MY_NUMBER` | MQL | No | Python | `jp_my_number_recognizer.py` | None | PII | Government ID | Japan | — | Done |
| 146 | Japan Passport Number | `JP_PASSPORT` | MQL | No | YAML | `jp_passport_recognizer.yml` | None | PII | Government ID | Japan | — | Done |
| 147 | Japan Social Insurance Number | `JP_SIN` | MQL | No | YAML | `jp_sin_recognizer.yml` | None | PII | Government ID | Japan | — | Done |

## 21. South Korea

| # | Entity Name | Entity Type Key | Source | Presidio Built-in? | Recognizer Route | File | Checksum | data_categories | data_types | regions | compliance | Status |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 148 | South Korea Resident Registration Number (RRN) | `KR_RRN` | MQL | Yes | — | `— (built-in: `KrRrnRecognizer`)` | — | PII | Government ID | South Korea | — | Done (built-in) |

## 22. China

| # | Entity Name | Entity Type Key | Source | Presidio Built-in? | Recognizer Route | File | Checksum | data_categories | data_types | regions | compliance | Status |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 149 | China Resident Identity Card Recognizer | `CN_RESIDENT_ID` | MQL | No | Python | `cn_resident_id_recognizer.py` | None | PII | Government ID | China | — | Done |

## 23. Taiwan

| # | Entity Name | Entity Type Key | Source | Presidio Built-in? | Recognizer Route | File | Checksum | data_categories | data_types | regions | compliance | Status |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 150 | Taiwan National ID Recognizer | `TW_NATIONAL_ID` | MQL | No | Python | `tw_national_id_recognizer.py` | None | PII | Government ID | Taiwan | — | Done |

## 24. Hong Kong

| # | Entity Name | Entity Type Key | Source | Presidio Built-in? | Recognizer Route | File | Checksum | data_categories | data_types | regions | compliance | Status |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 151 | Hong Kong Identity Card (HKID) Recognizer | `HK_IDENTITY_CARD` | MQL | No | Python | `hk_identity_card_recognizer.py` | None | PII | Government ID | Hong Kong | — | Done |

## 25. Southeast Asia (Singapore, Thailand)

| # | Entity Name | Entity Type Key | Source | Presidio Built-in? | Recognizer Route | File | Checksum | data_categories | data_types | regions | compliance | Status |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 152 | Singapore FIN | `SG_FIN` | MQL | No | YAML | `sg_fin_recognizer.yml` | None | PII | Government ID | Singapore | — | Done |
| 153 | Singapore UEN (Business Registration) | `SG_UEN` | MQL | No | YAML | `sg_uen_recognizer.yml` | None | Financial | Tax ID | Singapore | — | Done |
| 154 | Thailand TNIN (Thai National Identification Number) Recognizer | `TH_TNIN` | MQL | No | Python | `th_tnin_recognizer.py` | None | PII | Government ID | Thailand | — | Done |

## 26. Australia

| # | Entity Name | Entity Type Key | Source | Presidio Built-in? | Recognizer Route | File | Checksum | data_categories | data_types | regions | compliance | Status |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 155 | Australia ABN (Australian Business Number) Recognizer | `AU_ABN` | MQL | No | Python | `au_abn_recognizer.py` | None | Financial | Tax ID | Australia | — | Done |
| 156 | Australia ACN (Australian Company Number) Recognizer | `AU_ACN` | MQL | No | Python | `au_acn_recognizer.py` | None | Financial | Tax ID | Australia | — | Done |
| 157 | Australia BSB Code | `AU_BANK_ACCOUNT` | MQL | No | YAML | `au_bank_account_recognizer.yml` | None | Financial | Financial Account | Australia | — | Done |
| 158 | Australia Driver's License Number | `AU_DRIVERS_LICENSE` | MQL | No | YAML | `au_drivers_license_recognizer.yml` | None | PII | Government ID | Australia | — | Done |
| 159 | Australia Passport Number | `AU_PASSPORT` | MQL | No | YAML | `au_passport_recognizer.yml` | None | PII | Government ID | Australia | — | Done |
| 160 | Australia SWIFT Code | `AU_SWIFT_CODE` | MQL | No | YAML | `au_swift_code_recognizer.yml` | None | Financial | Financial Account | Australia | — | Done |
| 161 | Australia Tax File Number | `AU_TFN` | MQL | Yes | — | `— (built-in: `AuTfnRecognizer`)` | — | Financial | Tax ID | Australia | — | Done (built-in) |

## 27. New Zealand

| # | Entity Name | Entity Type Key | Source | Presidio Built-in? | Recognizer Route | File | Checksum | data_categories | data_types | regions | compliance | Status |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 162 | New Zealand Bank Account Number | `NZ_BANK_ACCOUNT` | MQL | No | YAML | `nz_bank_account_recognizer.yml` | None | Financial | Financial Account | New Zealand | — | Done |
| 163 | New Zealand Driver's License Number | `NZ_DRIVERS_LICENSE` | MQL | No | YAML | `nz_drivers_license_recognizer.yml` | None | PII | Government ID | New Zealand | — | Done |
| 164 | New Zealand IRD (Inland Revenue Department) Number Recognizer | `NZ_IRD` | MQL | No | Python | `nz_ird_recognizer.py` | None | Financial | Tax ID | New Zealand | — | Done |
| 165 | New Zealand Social Welfare Number | `NZ_SOCIAL_WELFARE` | MQL | No | YAML | `nz_social_welfare_recognizer.yml` | None | PII | Government ID | New Zealand | — | Done |

## 28. Middle East (Israel, Saudi Arabia)

| # | Entity Name | Entity Type Key | Source | Presidio Built-in? | Recognizer Route | File | Checksum | data_categories | data_types | regions | compliance | Status |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 166 | Israel Bank Account Number | `IL_BANK_ACCOUNT` | MQL | No | YAML | `il_bank_account_recognizer.yml` | None | Financial | Financial Account | Israel | — | Done |
| 167 | Israel National ID (Teudat Zehut) Recognizer | `IL_NATIONAL_ID` | MQL | No | Python | `il_national_id_recognizer.py` | None | PII | Government ID | Israel | — | Done |
| 168 | Israel SWIFT Code | `IL_SWIFT_CODE` | MQL | No | YAML | `il_swift_code_recognizer.yml` | None | Financial | Financial Account | Israel | — | Done |
| 169 | Saudi Arabia IBAN | `IBAN` | MQL | Yes | — | `— (built-in: `IbanRecognizer`)` | — | Financial | Financial Account | Saudi Arabia | — | Done (built-in) |
| 170 | Saudi Arabia National ID | `SA_NATIONAL_ID` | MQL | No | YAML | `sa_national_id_recognizer.yml` | None | PII | Government ID | Saudi Arabia | — | Done |
| 171 | Saudi Arabia SWIFT Code | `SA_SWIFT_CODE` | MQL | No | YAML | `sa_swift_code_recognizer.yml` | None | Financial | Financial Account | Saudi Arabia | — | Done |

## 29. Africa (Nigeria, South Africa)

| # | Entity Name | Entity Type Key | Source | Presidio Built-in? | Recognizer Route | File | Checksum | data_categories | data_types | regions | compliance | Status |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 172 | Nigeria National Identification Number | `NG_NIN` | MQL | No | YAML | `ng_nin_recognizer.yml` | None | PII | Government ID | Nigeria | — | Done |
| 173 | South Africa National ID Recognizer | `ZA_NATIONAL_ID` | MQL | No | Python | `za_national_id_recognizer.py` | None | PII | Government ID | South Africa | — | Done |

## 30. Latin America (Brazil, Mexico, Argentina, Chile, Colombia)

| # | Entity Name | Entity Type Key | Source | Presidio Built-in? | Recognizer Route | File | Checksum | data_categories | data_types | regions | compliance | Status |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 174 | Argentina CUIT/CUIL Recognizer | `AR_CUIT_CUIL` | MQL | No | Python | `ar_cuit_cuil_recognizer.py` | None | Financial | Tax ID | Argentina | — | Done |
| 175 | Argentina DNI Number | `AR_DNI` | MQL | No | YAML | `ar_dni_recognizer.yml` | None | PII | Government ID | Argentina | — | Done |
| 176 | Brazil CPF (Cadastro de Pessoas Fisicas) Recognizer | `BR_CPF` | MQL | No | Python | `br_cpf_recognizer.py` | None | Financial | Tax ID | Brazil | — | Done |
| 177 | Brazil RG Number | `BR_RG` | MQL | No | YAML | `br_rg_recognizer.yml` | None | PII | Government ID | Brazil | — | Done |
| 178 | Chile CDI (Cedula de Identidad / RUT) Recognizer | `CL_CDI` | MQL | No | Python | `cl_cdi_recognizer.py` | None | PII | Government ID | Chile | — | Done |
| 179 | Colombia Citizenship Card Number | `CO_CDC` | MQL | No | YAML | `co_cdc_recognizer.yml` | None | PII | Government ID | Colombia | — | Done |
| 180 | Mexico CURP (Clave Unica de Registro de Poblacion) Recognizer | `MX_CURP` | MQL | No | Python | `mx_curp_recognizer.py` | None | PII | Government ID | Mexico | — | Done |
| 181 | Mexico Passport Number | `MX_PASSPORT` | MQL | No | YAML | `mx_passport_recognizer.yml` | None | PII | Government ID | Mexico | — | Done |

## 31. Credit Cards / PCI

| # | Entity Name | Entity Type Key | Source | Presidio Built-in? | Recognizer Route | File | Checksum | data_categories | data_types | regions | compliance | Status |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 182 | Australia Credit Card Number | `CREDIT_CARD` | MQL | Yes | — | `— (built-in: `CreditCardRecognizer`)` | — | PCI | Payment Card | Australia | PCI-DSS | Done (built-in) |
| 183 | Canada Credit Card Number | `CREDIT_CARD` | MQL | Yes | — | `— (built-in: `CreditCardRecognizer`)` | — | PCI | Payment Card | Canada | PCI-DSS | Done (built-in) |
| 184 | DLP - PCI: American Express Credit Card Number | `CREDIT_CARD` | MQL | Yes | — | `— (built-in: `CreditCardRecognizer`)` | — | PCI | Payment Card | United States | PCI-DSS | Done (built-in) |
| 185 | DLP - PCI: Discover Credit Card Number | `CREDIT_CARD` | MQL | Yes | — | `— (built-in: `CreditCardRecognizer`)` | — | PCI | Payment Card | United States | PCI-DSS | Done (built-in) |
| 186 | DLP - PCI: Mastercard Credit Card Number | `CREDIT_CARD` | MQL | Yes | — | `— (built-in: `CreditCardRecognizer`)` | — | PCI | Payment Card | United States | PCI-DSS | Done (built-in) |
| 187 | DLP - PCI: US Credit Card Number (Any Network) | `CREDIT_CARD` | MQL | Yes | — | `— (built-in: `CreditCardRecognizer`)` | — | PCI | Payment Card | Global | PCI-DSS | Done (built-in) |
| 188 | DLP - PCI: Visa Credit Card Number | `CREDIT_CARD` | MQL | Yes | — | `— (built-in: `CreditCardRecognizer`)` | — | PCI | Payment Card | United States | PCI-DSS | Done (built-in) |
| 189 | EU Debit Card Number | `CREDIT_CARD` | MQL | Yes | — | `— (built-in: `CreditCardRecognizer`)` | — | PCI | Payment Card | European Union | PCI-DSS, GDPR | Done (built-in) |
| 190 | France Credit Card Number | `CREDIT_CARD` | MQL | Yes | — | `— (built-in: `CreditCardRecognizer`)` | — | PCI | Payment Card | France | PCI-DSS | Done (built-in) |
| 191 | France Debit Card Number | `CREDIT_CARD` | MQL | Yes | — | `— (built-in: `CreditCardRecognizer`)` | — | PCI | Payment Card | France | PCI-DSS | Done (built-in) |
| 192 | Israel Credit Card Number | `CREDIT_CARD` | MQL | Yes | — | `— (built-in: `CreditCardRecognizer`)` | — | PCI | Payment Card | Israel | PCI-DSS | Done (built-in) |
| 193 | Japan Credit Card Number | `CREDIT_CARD` | MQL | Yes | — | `— (built-in: `CreditCardRecognizer`)` | — | PCI | Payment Card | Japan | PCI-DSS | Done (built-in) |

## 32. Credentials & Secrets

| # | Entity Name | Entity Type Key | Source | Presidio Built-in? | Recognizer Route | File | Checksum | data_categories | data_types | regions | compliance | Status |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 194 | ASP.NET Machine Key | `ASPNET_MACHINE_KEY` | Purview | No | YAML | `aspnet_machine_key_recognizer.yml` | None | Credentials | Cryptographic Material | Global | — | Done |
| 195 | AWS Access Key ID | `AWS_ACCESS_KEY` | MQL | No | YAML | `aws_access_key_recognizer.yml` | None | Credentials | API Key | Global | — | Done |
| 196 | Azure App Service Deployment Password | `AZURE_APP_SERVICE_DEPLOYMENT_PASSWORD` | Purview | No | YAML | `azure_app_service_deployment_password_recognizer.yml` | None | Credentials | Authentication Token | Global | — | Done |
| 197 | Azure Authentication Token | `AZURE_AUTH_TOKEN` | MQL | No | YAML | `azure_auth_token_recognizer.yml` | None | Credentials | Authentication Token | Global | — | Done |
| 198 | Azure Batch Shared Access Key | `AZURE_BATCH_SHARED_ACCESS_KEY` | Purview | No | YAML | `azure_batch_shared_access_key_recognizer.yml` | None | Credentials | API Key | Global | — | Done |
| 199 | Azure Bot Framework Secret Key | `AZURE_BOT_FRAMEWORK_SECRET_KEY` | Purview | No | YAML | `azure_bot_framework_secret_key_recognizer.yml` | None | Credentials | API Key | Global | — | Done |
| 200 | Azure Container Registry Access Key | `AZURE_CONTAINER_REGISTRY_ACCESS_KEY` | Purview | No | YAML | `azure_container_registry_access_key_recognizer.yml` | None | Credentials | API Key | Global | — | Done |
| 201 | Azure Cosmos DB Account Access Key | `AZURE_COSMOS_DB_ACCESS_KEY` | Purview | No | YAML | `azure_cosmos_db_access_key_recognizer.yml` | None | Credentials | API Key | Global | — | Done |
| 202 | Azure Databricks Personal Access Token | `AZURE_DATABRICKS_PAT` | Purview | No | YAML | `azure_databricks_pat_recognizer.yml` | None | Credentials | Authentication Token | Global | — | Done |
| 203 | Azure DevOps Personal Access Token | `AZURE_DEVOPS_PAT` | Purview | No | YAML | `azure_devops_pat_recognizer.yml` | None | Credentials | Authentication Token | Global | — | Done |
| 204 | Azure DocumentDB Auth Key | `AZURE_DOCUMENTDB_AUTH_KEY` | Purview | No | YAML | `azure_documentdb_auth_key_recognizer.yml` | None | Credentials | API Key | Global | — | Done |
| 205 | Azure EventGrid Access Key | `AZURE_EVENTGRID_ACCESS_KEY` | Purview | No | YAML | `azure_eventgrid_access_key_recognizer.yml` | None | Credentials | API Key | Global | — | Done |
| 206 | Azure Function Master/API Key | `AZURE_FUNCTION_KEY` | Purview | No | YAML | `azure_function_key_recognizer.yml` | None | Credentials | API Key | Global | — | Done |
| 207 | Azure IoT Connection String | `AZURE_IOT_CONNECTION_STRING` | Purview | No | YAML | `azure_iot_connection_string_recognizer.yml` | None | Credentials | Connection String | Global | — | Done |
| 208 | Azure Logic App Shared Access Signature | `AZURE_LOGIC_APP_SAS` | Purview | No | YAML | `azure_logic_app_sas_recognizer.yml` | None | Credentials | Authentication Token | Global | — | Done |
| 209 | Azure ML Web Service API Key | `AZURE_ML_WEB_SERVICE_KEY` | Purview | No | YAML | `azure_ml_web_service_key_recognizer.yml` | None | Credentials | API Key | Global | — | Done |
| 210 | Azure Maps Subscription Key | `AZURE_MAPS_SUBSCRIPTION_KEY` | Purview | No | YAML | `azure_maps_subscription_key_recognizer.yml` | None | Credentials | API Key | Global | — | Done |
| 211 | Azure Redis Cache Connection String | `AZURE_REDIS_CONNECTION_STRING` | Purview | No | YAML | `azure_redis_connection_string_recognizer.yml` | None | Credentials | Connection String | Global | — | Done |
| 212 | Azure SAS Token | `AZURE_SAS_TOKEN` | Purview | No | YAML | `azure_sas_token_recognizer.yml` | None | Credentials | Authentication Token | Global | — | Done |
| 213 | Azure SQL Server Connection String | `AZURE_SQL_CONNECTION_STRING` | Purview | No | YAML | `azure_sql_connection_string_recognizer.yml` | None | Credentials | Connection String | Global | — | Done |
| 214 | Azure Service Bus Connection String | `AZURE_SERVICE_BUS_CONNECTION_STRING` | Purview | No | YAML | `azure_service_bus_connection_string_recognizer.yml` | None | Credentials | Connection String | Global | — | Done |
| 215 | Azure SignalR Access Key | `AZURE_SIGNALR_ACCESS_KEY` | Purview | No | YAML | `azure_signalr_access_key_recognizer.yml` | None | Credentials | API Key | Global | — | Done |
| 216 | Azure Storage Account Access Key | `AZURE_STORAGE_ACCOUNT_KEY` | Purview | No | YAML | `azure_storage_account_key_recognizer.yml` | None | Credentials | API Key | Global | — | Done |
| 217 | Azure Subscription Management Certificate | `AZURE_SUBSCRIPTION_MGMT_CERT` | Purview | No | YAML | `azure_subscription_mgmt_cert_recognizer.yml` | None | Credentials | Cryptographic Material | Global | — | Done |
| 218 | Basic Authentication Header | `BASIC_AUTH_HEADER` | MQL | No | YAML | `basic_auth_header_recognizer.yml` | None | Credentials | Authentication Token | Global | — | Done |
| 219 | Client Secret or API Key (Generic) | `CLIENT_SECRET_API_KEY` | Purview | No | YAML | `client_secret_api_key_recognizer.yml` | None | Credentials | API Key | Global | — | Done |
| 220 | GCP API Key | `GCP_API_KEY` | MQL | No | YAML | `gcp_api_key_recognizer.yml` | None | Credentials | API Key | Global | — | Done |
| 221 | General Password | `GENERAL_PASSWORD` | Purview | No | YAML | `general_password_recognizer.yml` | None | Credentials | Authentication Token | Global | — | Done |
| 222 | General Symmetric Key | `GENERAL_SYMMETRIC_KEY` | Purview | No | YAML | `general_symmetric_key_recognizer.yml` | None | Credentials | Cryptographic Material | Global | — | Done |
| 223 | GitHub Token | `GITHUB_TOKEN` | MQL | No | YAML | `github_token_recognizer.yml` | None | Credentials | Authentication Token | Global | — | Done |
| 224 | JSON Web Token | `JSON_WEB_TOKEN` | MQL | No | YAML | `json_web_token_recognizer.yml` | None | Credentials | Authentication Token | Global | — | Done |
| 225 | Microsoft Bing Maps Key | `BING_MAPS_KEY` | Purview | No | YAML | `bing_maps_key_recognizer.yml` | None | Credentials | API Key | Global | — | Done |
| 226 | Microsoft Entra Client Secret | `ENTRA_CLIENT_SECRET` | Purview | No | YAML | `entra_client_secret_recognizer.yml` | None | Credentials | Authentication Token | Global | — | Done |
| 227 | OAuth Client Secret | `OAUTH_CLIENT_SECRET` | MQL | No | YAML | `oauth_client_secret_recognizer.yml` | None | Credentials | Authentication Token | Global | — | Done |
| 228 | Private Key | `PRIVATE_KEY` | MQL | No | YAML | `private_key_recognizer.yml` | None | Credentials | Cryptographic Material | Global | — | Done |
| 229 | SQL Server Connection String | `SQL_SERVER_CONNECTION_STRING` | Purview | No | YAML | `sql_server_connection_string_recognizer.yml` | None | Credentials | Connection String | Global | — | Done |
| 230 | SSL Certificate | `SSL_CERTIFICATE` | MQL | No | YAML | `ssl_certificate_recognizer.yml` | None | Credentials | Cryptographic Material | Global | — | Done |
| 231 | Slack Token | `SLACK_TOKEN` | MQL | No | YAML | `slack_token_recognizer.yml` | None | Credentials | Authentication Token | Global | — | Done |
| 232 | User Login Credentials | `USER_LOGIN_CREDENTIALS` | Purview | No | YAML | `user_login_credentials_recognizer.yml` | None | Credentials | Authentication Token | Global | — | Done |

## 33. Medical / Pharma

| # | Entity Name | Entity Type Key | Source | Presidio Built-in? | Recognizer Route | File | Checksum | data_categories | data_types | regions | compliance | Status |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 233 | Australia Medical Account Number | `AU_MEDICARE` | MQL | Yes | — | `— (built-in: `AuMedicareRecognizer`)` | — | PII, PHI | Healthcare ID | Australia | — | Done (built-in) |
| 234 | Blood Test Terms | `BLOOD_TEST_TERM` | Purview | No | YAML | `blood_test_term_recognizer.yml` | None | PHI | Medical Code | Global | HIPAA | Done |
| 235 | Canada Health Service Number | `CA_HEALTH_SERVICE` | MQL | No | YAML | `ca_health_service_recognizer.yml` | None | PII, PHI | Healthcare ID | Canada | — | Done |
| 236 | Canada Personal Health Identification Number | `CA_PHIN` | MQL | No | YAML | `ca_phin_recognizer.yml` | None | PII, PHI | Healthcare ID | Canada | — | Done |
| 237 | FDA Drug Names | `FDA_DRUG_NAME` | Purview | No | YAML | `fda_drug_name_recognizer.yml` | None | PHI | Medical Code | Global | HIPAA | Done |
| 238 | Finland European Health Insurance Card Number | `FI_EUROPEAN_HEALTH_INSURANCE` | Purview | No | YAML | `fi_european_health_insurance_recognizer.yml` | None | PII | Health Insurance | Finland | GDPR | Done |
| 239 | France Health Insurance Number | `FRANCE_HEALTH_INSURANCE` | Purview | No | YAML | `france_health_insurance.yml` | None | PII | Healthcare | France | GDPR | Done |
| 240 | Medical Conditions | `MEDICAL_CONDITION` | Purview | No | YAML | `medical_conditions_recognizer.yml` | None | PHI | Medical Code | Global | HIPAA | Done |
| 241 | Medical Specialties | `MEDICAL_SPECIALTY` | Purview | No | YAML | `medical_specialty_recognizer.yml` | None | PHI | Medical Code | Global | HIPAA | Done |
| 242 | New Zealand Ministry of Health Number (NHI) | `NZ_MOH` | MQL | No | YAML | `nz_moh_recognizer.yml` | None | PII, PHI | Healthcare ID | New Zealand | — | Done |
| 243 | Recognizer for US Drug Enforcement Administration (DEA) registration numbers | `US_DEA_NUMBER` | Purview | No | Python | `us_dea_number_recognizer.py` | None | PII, PHI | Healthcare ID | United States | HIPAA | Done |
| 244 | Surgical Procedures | `SURGICAL_PROCEDURE` | Purview | No | YAML | `surgical_procedure_recognizer.yml` | None | PHI | Medical Code | Global | HIPAA | Done |
| 245 | US Disability Impairments | `US_DISABILITY_IMPAIRMENT` | Purview | No | YAML | `us_disability_impairment_recognizer.yml` | None | PII, PHI | Medical Code | United States | HIPAA | Done |
| 246 | US ICD-10-CM Code | `US_ICD10` | MQL | No | YAML | `us_icd10_recognizer.yml` | None | PII, PHI | Medical Code | United States | HIPAA | Done |
| 247 | US ICD-9-CM Code | `US_ICD9` | MQL | No | YAML | `us_icd9_recognizer.yml` | None | PII, PHI | Medical Code | United States | HIPAA | Done |
| 248 | US Insurance Claim Number | `US_INSURANCE_CLAIM` | MQL | No | YAML | `us_insurance_claim_recognizer.yml` | None | PII, PHI | Healthcare ID | United States | HIPAA | Done |
| 249 | US Medicare Beneficiary ID | `US_MEDICARE_BENEFICIARY_ID` | Purview | No | YAML | `us_medicare_beneficiary_recognizer.yml` | None | PII, PHI | Healthcare ID | United States | HIPAA | Done |

## 34. Network / Device

| # | Entity Name | Entity Type Key | Source | Presidio Built-in? | Recognizer Route | File | Checksum | data_categories | data_types | regions | compliance | Status |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 250 | IMSI Number | `IMSI` | MQL | No | YAML | `imsi_recognizer.yml` | None | Network Identifiers | Device Identifier | Global | — | Done |
| 251 | IP Address | `IP_ADDRESS` | MQL | Yes | — | `— (built-in: `IpRecognizer`)` | — | Network Identifiers | Network Address | Global | — | Done (built-in) |
| 252 | MAC Address | `MAC_ADDRESS` | MQL | Yes | — | `— (built-in: `MacAddressRecognizer`)` | — | Network Identifiers | Device Identifier | Global | — | Done (built-in) |
| 253 | Recognizer for International Mobile Equipment Identity (IMEI) numbers | `IMEI` | MQL | No | Python | `imei_recognizer.py` | None | Network Identifiers | Device Identifier | Global | — | Done |
| 254 | Recognizer for Vehicle Identification Numbers (VIN) | `VEHICLE_VIN` | MQL | No | Python | `vehicle_vin_recognizer.py` | None | PII | Device Identifier | Global | — | Done |

---

## Summary

| Metric | Count |
|---|---|
| Total entries | 254 |
| Custom recognizers (YAML) | 170 |
| Custom recognizers (Python) | 43 |
| Presidio built-in | 41 |
| MQL rules total | 254 |
| Unique entity types | 242 |
