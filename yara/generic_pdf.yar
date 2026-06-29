rule pwd_protected_pdf_fake_document_1
{
    meta:
        author = "kyle eaton"
        description = "password protected PDF matching several observed lures. Rule is looking at a few of the object nubmer/object type pairs that we saw consistent across the samples. "
    strings:
        $header = {25 50 44 46 2d 31 2e}
        $s1 = {31 33 20 30 20 6F 62 6A 0A 3C 3C 20 20 2F 54 79 70 65 20 2F 43 61 74 61 6C 6F 67} // object 13 is type catalog
        $s2 = {35 20 30 20 6F 62 6A 0A 3C 3C 2F 54 79 70 65 20 2F 46 6F 6E 74} // object 5 is type font
        $s3 = {36 20 30 20 6F 62 6A 0A 3C 3C 2F 54 79 70 65 20 2F 41 6E 6E 6F 74 20 2F 53 75 62 74 79 70 65 20 2F 4C 69 6E 6B 20 2F 52 65 63 74 } // object 6 is link annot with rect
        $s4 = {37 20 30 20 6F 62 6A 0A 3C 3C 2F 54 79 70 65 20 2F 41 6E 6E 6F 74 20 2F 53 75 62 74 79 70 65 20 2F 4C 69 6E 6B } // obj 7 is link annot with rect.
    condition:
        $header at 0
        and all of ($s*)
}

rule w9_pdf_01 {
    meta:
        author = "kyle eaton"
        date = "2026-01-23"
        updated = "2026-03-10"
        description = "matching PDF observed in fake w9/invoice campaigns. Focusing on some of the object values found in the w9 lures, as well as some of the embedded images."
    strings:
        $header = {25 50 44 46 2D 31 2E}
        $lw_01 = {2F 4C 57 20 31 2E 35 32 36 39 39 39 39 35 0A 2F 4D 4C 20 31 30}
        $lw_02 = {2F 4C 57 20 2E 37 36 33 30 30 30 30 31 0A 2F 4D 4C 20 31 30}
        $lw_03 = {2F 4C 57 20 31 2E 31 34 34 39 39 39 39 38 0A 2F 4D 4C 20 31 30}
        $jpg_blue_signature = {00 00 33 A3 42 55 DF 24 13 94 9E CA 29 B7 8C EC 8B 0A 3F 27 2A C9 73 4D 28 26 BE 9B B3 DE D6 E5 49 C9 7C 52 C7 C0 CA B5 B5 A7 51 0F 26 D1 5F 2A C0 5B}
        $jpg_w9_form = {8A B4 B4 3F F8 FE 4F A1 FE 55 9B 57 F4 33 FF 00 13 25 1E C7 F9 50 07 51 45 14 50 01 45 14 50 01 45 14 50 01 45 14 50 01 45 14 50 01 45 14 50 01 45 14 50 01 45 14 50 01 45 14 50 01 45 14 50 01 45 14 50 01 45 14 50 01 45 14 50 01 45 14 50 01 45 14 50 01 45 14 50 01 45 14 50 01 45 14 50 01 45 14 50 01 45 14 50 01}
    condition:
        $header at 0
        and (
            any of ($lw_*)
            or any of ($jpg_*)
        )
}

rule w9_pdf_IDs {
    meta:
        author = "kyle eaton"
        date = "2026-03-12"
        description = "matching PDF ID values from a few malicious/fake w9 documents." 
    strings:
        $header = {25 50 44 46 2D 31 2E}
        $id1 = {5B 3C 33 34 39 31 30 37 35 38 46 39 38 32 31 46 37 32 33 46 41 34 30 30 39 38 46 41 30 34 36 35 36 42 3E 20 3C 33 34 39 31 30 37 35 38 46 39 38 32 31 46 37 32 33 46 41 34 30 30 39 38 46 41 30 34 36 35 36 42 3E 5D}
        $id2 = {5B 3C 38 65 61 37 33 35 61 36 33 33 61 30 30 35 36 38 32 66 31 32 33 62 61 36 63 61 36 36 61 38 34 63 3E 3C 38 65 61 37 33 35 61 36 33 33 61 30 30 35 36 38 32 66 31 32 33 62 61 36 63 61 36 36 61 38 34 63 3E 5D}
    condition:
        $header at 0
        and any of ($id*)
}

rule w9_pdf_images {
    meta:
        author      = "kyle eaton"
        date        = "2026-05-12"
        description = "pdfs with images associated with FAKE w9s and invoices, often the signatures or fake company logos"
    strings:
        $header           = { 25 50 44 46 2D 31 2E }
        $jpg_signature_01 = { 60 1E 46 70 7A 8A 00 D5 A2 8A 28 00 A2 8A 28 00 A2 8A 28 00 A8 16 EA D5 EE 1E D1 25 46 9A 30 0B 46 }
        $jpg_signature_02 = { B7 D2 2E 00 3D EB E0 AF FC 15 F3 F6 EB F8 DF F0 8F E1 97 C6 BF 86 9F F0 45 5F DA 83 E2 07 C2 4F }
    condition:
        $header at 0
        and any of ($jpg_*)
}

rule w9_pdf_fonts {
    meta:
        author      = "kyle eaton"
        date        = "2026-05-12"
        description = "PDFs with specific fonts (based on type/length), as observed in fake w9 messages"
    strings:
        $header     = { 25 50 44 46 2D 31 2E }
        $font_17_01 = { 2F 4C 65 6E 67 74 68 20 36 36 34 0A 2F 53 75 62 74 79 70 65 20 2F 54 79 70 65 31 43 }
        $font_17_02 = { 2F 4C 65 6E 67 74 68 20 32 31 32 33 0A 2F 53 75 62 74 79 70 65 20 2F 54 79 70 65 31 43 }
        $font_17_03 = { 2F 4C 65 6E 67 74 68 20 34 37 39 31 0A 2F 53 75 62 74 79 70 65 20 2F 54 79 70 65 31 43 }
        $font_16_01 = { 2F 4C 65 6E 67 74 68 20 34 36 39 34 2F 53 75 62 74 79 70 65 2F 54 79 70 65 31 43 }
        $font_16_02 = { 2F 4C 65 6E 67 74 68 20 36 36 33 2F 53 75 62 74 79 70 65 2F 54 79 70 65 31 43 }
        $font_16_03 = { 2F 4C 65 6E 67 74 68 20 32 31 31 31 2F 53 75 62 74 79 70 65 2F 54 79 70 65 31 43 }
    condition:
        $header at 0
        and (all of ($font_17_*) or all of ($font_16_*))
}

rule invoice_pdf_01 {
    meta:
        author = "kyle eaton"
        date = "2026-01-23"
        description = "matching PDF observed in fake w9/invoice campaigns. This focuses on the images found in some of the invoice lures."
    strings:
        $header = {25 50 44 46 2D 31 2E}
        $jpg_jump_logo_dots = {ffc00011080062006b03011100021101031101ffc401a20000010501010101010100000000000000000102030405060708090a0b100002010303020403050504040000017d01020300041105122131410613516107227114328191a1082342b1c11552d1f02433627282090a161718191a25262728292a3435363738393a434445464748494a535455565758595a636465666768696a737475767778797a838485868788898a92939495969798999aa2a3a4a5a6a7a8a9aab2b3b4b5b6b7b8b9bac2c3c4c5c6c7c8c9cad2d3d4d5d6d7d8d9dae1e2e3e4e5e6e7e8e9eaf1f2f3f4f5f6f7f8f9fa0100030101010101010101010000000000000102030405060708090a0b1100020102040403040705040400010277000102031104052131061241510761711322328108144291a1b1c109233352f0156272d10a162434e125f11718191a262728292a35363738393a434445464748494a535455565758595a636465666768696a737475767778797a82838485868788898a92939495969798999aa2a3a4a5a6a7a8a9aab2b3b4b5b6b7b8b9bac2c3c4c5c6c7c8c9cad2d3d4d5d6d7d8d9dae2e3e4e5e6e7e8e9eaf2f3f4f5f6f7f8f9faffda000c03010002110311003f00fb2a801a7ad00148635dd5177310aa3a9270055589b90c57b69348522ba85d8750ae0d3b315c9cfd718a929115c5c43026e9a448d47766c53b0362db5c433a6e8658e41eaad9a2c24ee4a7839ebed486567bfb28e6f2}
        $jpg_jump_page_break = {ffc00011080004034f03011100021101031101ffc401a20000010501010101010100000000000000000102030405060708090a0b100002010303020403050504040000017d01020300041105122131410613516107227114328191a1082342b1c11552d1f02433627282090a161718191a25262728292a3435363738393a434445464748494a535455565758595a636465666768696a737475767778797a838485868788898a92939495969798999aa2a3a4a5a6a7a8a9aab2b3b4b5b6b7b8b9bac2c3c4c5c6c7c8c9cad2d3d4d5d6d7d8d9dae1e2e3e4e5e6e7e8e9eaf1f2f3f4f5f6f7f8f9fa0100030101010101010101010000000000000102030405060708090a0b1100020102040403040705040400010277000102031104052131061241510761711322328108144291a1b1c109233352f0156272d10a162434e125f11718191a262728292a35363738393a434445464748494a535455565758595a636465666768696a737475767778797a82838485868788898a92939495969798999aa2a3a4a5a6a7a8a9aab2b3b4b5b6b7b8b9bac2c3c4c5c6c7c8c9cad2d3d4d5d6d7d8d9dae2e3e4e5e6e7e8e9eaf2f3f4f5f6f7f8f9faffda000c03010002110311003f00fb09ad7314b1fda2e0798dbb707e57d87a0a007f93fbff0037cd97ee6dd9bbe5fae3d680182d711471fda2e0ec6ddb8bf2dec4f71400a6df2d31f3a61e68c6037dcff77d28014418684f9d31f28631bb87ff007bd680}
        $jpg_jump_logo_geo = {ffc0001108007e008403011100021101031101ffc401a20000010501010101010100000000000000000102030405060708090a0b100002010303020403050504040000017d01020300041105122131410613516107227114328191a1082342b1c11552d1f02433627282090a161718191a25262728292a3435363738393a434445464748494a535455565758595a636465666768696a737475767778797a838485868788898a92939495969798999aa2a3a4a5a6a7a8a9aab2b3b4b5b6b7b8b9bac2c3c4c5c6c7c8c9cad2d3d4d5d6d7d8d9dae1e2e3e4e5e6e7e8e9eaf1f2f3f4f5f6f7f8f9fa0100030101010101010101010000000000000102030405060708090a0b1100020102040403040705040400010277000102031104052131061241510761711322328108144291a1b1c109233352f0156272d10a162434e125f11718191a262728292a35363738393a434445464748494a535455565758595a636465666768696a737475767778797a82838485868788898a92939495969798999aa2a3a4a5a6a7a8a9aab2b3b4b5b6b7b8b9bac2c3c4c5c6c7c8c9cad2d3d4d5d6d7d8d9dae2e3e4e5e6e7e8e9eaf2f3f4f5f6f7f8f9faffda000c03010002110311003f00fb2a800a002800a002800a002800a002800a002800a002800a002800a002800a002800a002800a002800a002800a002800a0028029eaba9586976a6e750ba8ede21ddcf5f603b9a00f34d7fe23dc5fea10d8e8a8d6d6}
    condition:
        $header at 0
        and any of ($jpg_*) 
}

rule view_document_pdf_characteristics
{
    meta:
        author = "kyle eaton"
        description = "PDF contains generic lure image characteristics. 'VIEW DOCUMENT HERE' with blurred document image present."
    strings:
        $header = {25 50 44 46 2D 31 2E}
        $image_w = "/Width 1200"
        $image_h = "/Height 1067"
        $uri = "/URI"
        $mb = "/MediaBox [0 0 612 792]"
        $prod = "/Producer"
    condition:
        $header at 0
        and $mb
        and $prod
        and $uri
        and @image_h == @image_w + 12

}

rule pdf_suspicious_image_001
{
    meta:
        author = "kyle eaton"
        description = "PDF contains a suspicious 'confidential' notice image observed in phishing campaigns."
    strings:
        $header = {25 50 44 46 2d 31 2e}
        $jpg_confidential_notice = {ffc00011080052026f03012200021101031101ffc4001f0000010501010101010100000000000000000102030405060708090a0bffc400b5100002010303020403050504040000017d01020300041105122131410613516107227114328191a1082342b1c11552d1f02433627282090a161718191a25262728292a3435363738393a434445464748494a535455565758595a636465666768696a737475767778797a838485868788898a92939495969798999aa2a3a4a5a6a7a8a9aab2b3b4b5b6b7b8b9bac2c3c4c5c6c7c8c9cad2d3d4d5d6d7d8d9dae1e2e3e4e5e6e7e8e9eaf1f2f3f4f5f6f7f8f9faffc4001f0100030101010101010101010000000000000102030405060708090a0bffc400b51100020102040403040705040400010277000102031104052131061241510761711322328108144291a1b1c109233352f0156272d10a162434e125f11718191a262728292a35363738393a434445464748494a535455565758595a636465666768696a737475767778797a82838485868788898a92939495969798999aa2a3a4a5a6a7a8a9aab2b3b4b5b6b7b8b9bac2c3c4c5c6c7c8c9cad2d3d4d5d6d7d8d9dae2e3e4e5e6e7e8e9eaf2f3f4f5f6f7f8f9faffda000c03010002110311003f00eef59bdbdb148e5b78e078de58e2c48c4105dc2e78edc8aad2eb8f63a8cb6f7e836476f1cacd023305dcce0927d30abfad69dfd9a5f42913b32849639415f5460c07e62abdee9115e3de33c8ebf6a81606c6380a58e4}
        $jpg_pinkish_lure = {ffc00011080182039a03012200021101031101ffc4001f0000010501010101010100000000000000000102030405060708090a0bffc400b5100002010303020403050504040000017d01020300041105122131410613516107227114328191a1082342b1c11552d1f02433627282090a161718191a25262728292a3435363738393a434445464748494a535455565758595a636465666768696a737475767778797a838485868788898a92939495969798999aa2a3a4a5a6a7a8a9aab2b3b4b5b6b7b8b9bac2c3c4c5c6c7c8c9cad2d3d4d5d6d7d8d9dae1e2e3e4e5e6e7e8e9eaf1f2f3f4f5f6f7f8f9faffc4001f0100030101010101010101010000000000000102030405060708090a0bffc400b51100020102040403040705040400010277000102031104052131061241510761711322328108144291a1b1c109233352f0156272d10a162434e125f11718191a262728292a35363738393a434445464748494a535455565758595a636465666768696a737475767778797a82838485868788898a92939495969798999aa2a3a4a5a6a7a8a9aab2b3b4b5b6b7b8b9bac2c3c4c5c6c7c8c9cad2d3d4d5d6d7d8d9dae2e3e4e5e6e7e8e9eaf2f3f4f5f6f7f8f9faffda000c03010002110311003f00e7e8 [ 344 ] 7a00326b7347f0d4f7b17daef241696639323f048f6abb2ebfa668ea60d0ed11e41c1b990673f4a2e62eaebcb057653b2f096a7708249c25a45fde98e0fe5564e95e19b0e2f7557b871d5211c7e95857da9df6a0}
    condition:
        $header at 0
        and any of ($jpg*)
}

rule rmm_pdf_lure {
    meta:
        authors = "kyle eaton, mark morris"
        date = "2026-03-18"
        description = "matching PDFs with specific left and right rect values - seen in RMM delivery documents"
    strings:
        $header = {25 50 44 46 2D 31 2E}
        $link1 = {2f 52 65 63 74 20 5b 31 37 34 2e 37 35 [5-8] 32 31 36 2e 37 35}
    condition:
        $header at 0 and
        $link1
}

rule SAI_Global_ISO9001_Logo_PDF_Fuzzy                                                                                                                                    
{                                                                                                                                                                       
   meta:
       author = "brandon murphy"
       date = "2026-04-09"
       description = "fuzzy detection of SAI Global ISO 9001 logo variants in PDFs (re-encoded, resized)"

  strings:
        // PDF markers
        $pdf_header   = "%PDF"
        $is_image     = "/Subtype /Image"
        $is_jpeg      = "/Filter /DCTDecode"

        // JPEG quantization table — shorter anchor (16 bytes from luma QT)
        // This specific sequence of QT values is rare and survives minor edits
        $qt_anchor = {
            14 14 14 14 15 14 17 19
            19 17 1F 22 1E 22 1F 2E
        }

        // SOF progressive marker with 1024x768
        $sof_1024x768 = { FF C2 00 11 08 03 00 04 00 }

        // Alternate: SOF baseline with 1024x768
        $sof_baseline = { FF C0 00 11 08 03 00 04 00 }

        // Unique scan-data byte patterns (mid-stream anchors)
        // From ~25% into the JPEG scan data
        $scan_mid1 = { 14 20 31 41 51 53 60 71 15 40 52 72 22 33 34 35 }
        // From ~50% into the JPEG scan data
        $scan_mid2 = { E6 0F 4A FA F9 6D 97 45 75 C8 69 DD 9D 8B 31 CC }

    condition:
        $pdf_header at 0 and
        $is_image and $is_jpeg and
        (
            // High confidence: QT match + dimensions
            ($qt_anchor and ($sof_1024x768 or $sof_baseline))
            or
            // Medium confidence: QT match + scan data anchor
            ($qt_anchor and ($scan_mid1 or $scan_mid2))
        )
}

rule pdf_jsfck_ratio {
    meta:
        author      = "kyle eaton"
        date        = "04.13.2026"
        description = "matching PDFs which contain JS objects which have a high ratio (40%) of characters used in jsf-ck obfuscation "
    strings:
        $header   = { 25 50 44 46 2D 31 2E }
        $js       = "/JS"
        $a        = "["
        $b        = "]"
        $c        = "+"
        $d        = "{"
        $e        = "}"
        $js_regex = /\/JS\s+?\((.*?)\)\s+?.*?>>/s
    condition:
        $header at 0
        and all of them
        and for any i in (1..#js_regex): (
            ((#a in (@js_regex[i]..@js_regex[i] + !js_regex) + #b in (@js_regex[i]..@js_regex[i] + !js_regex) + #c in (@js_regex[i]..@js_regex[i] + !js_regex) + #d in (@js_regex[i]..@js_regex[i] + !js_regex) + #e in (@js_regex[i]..@js_regex[i] + !js_regex) * 1.0) \ !js_regex * 100) > 40

        )
}

rule pdf_jsfck_strings {
    meta:
        author      = "kyle eaton"
        date        = "04.13.2026"
        description = "matching PDFs which contain JS objects using jsf-ck obfuscation."
    strings:
        $header   = { 25 50 44 46 2D 31 2E }
        $js_regex = /\/JS\s+?\((.*?)\)\s+?.*?>>/s
        $jsf01    = "({}+[])"
        $jsf02    = "(!+[]/+[]+[])"
        $jsf03    = "[][[]]"
        $jsf04    = "+[![]]"
        $jsf05    = "+[]"
        $jsf06    = "+!+[]"
        $jsf07    = "!+[]+!+[]"
        $jsf08    = "[[+!+[]]]"
    condition:
        $header at 0
        and $js_regex
        and for any i in (1..#js_regex): (
            any of ($jsf*) in (@js_regex[i]..@js_regex[i] + !js_regex)
        )
}

rule pdf_acro_js_functions {
    meta:
        author      = "kyle eaton"
        date        = "04.13.2026"
		description = "matching PDFs which use JS to load content from other objects with in the PDF OR pdfs that use exploited functions that we've observed used maliciously."
	strings:
		$header      = { 25 50 44 46 2D 31 2E }
		$js_regex    = /\/JS\s+?\((.*?)\)\s+?.*?>>/s
		$acro_1      = "SOAP"
		$acro_2      = "util"
		$getField    = "getField"
		$fancy_b64_1 = "FORmFuY3lBbGVydEltcGwo"
		$fancy_b64_2 = "QU5GYW5jeUFsZXJ0SW1wbC"
		$fancy_b64_3 = "BTkZhbmN5QWxlcnRJbXBsK"
	condition:
		$header at 0
		and $js_regex
		and for any i in (1..#js_regex): (
			(
				any of ($acro_*) in (@js_regex[i]..@js_regex[i] + !js_regex)
				and $getField in (@js_regex[i]..@js_regex[i] + !js_regex))
			or (
				any of ($fancy_b64_*) in (@js_regex[i]..@js_regex[i] + !js_regex)
			)
		)
}

rule pdf_b64_js_var_eval {
	meta:
		author      = "kyle eaton"
		date        = "04.13.2026"
		description = "matching pdfs with base64 encoded javascript that either start with var, or include the eval string."
	strings:
		$header        = { 25 50 44 46 2D 31 2E }
		$b64_var_start = " /V /dmFyI"
		$eval_b64_1    = "ZXZhbC"
		$eval_b64_2    = "V2YWwo"
		$eval_b64_3    = "ldmFsK"
	condition:
		$header at 0
		and $b64_var_start
		and any of ($eval_b64_*)
}

rule pdf_cve_2026_34621_observed_lures {
	meta:
		author      = "kyle eaton"
		date        = "04.14.2026"
		description = "matches the lures in the PDFs observed exploiting CVE-2026-34621."
	strings:
		$header = { 25 50 44 46 2D 31 2E }
		$img_1  = { ff c0 00 11 08 03 18 02 64 03 01 22 00 02 11 01 03 11 01 ff c4 00 1f 00 00 01 05 01 01 01 01 01 01 00 00 00 00 00 00 00 00 01 02 03 04 05 06 07 08 09 0a 0b ff c4 00 b5 10 00 02 01 03 03 02 04 03 05 05 04 04 00 00 01 7d 01 02 03 00 04 11 05 12 21 31 41 06 13 51 61 07 22 71 14 32 81 91 a1 08 23 42 b1 c1 15 52 d1 f0 24 33 62 72 82 09 0a 16 17 18 19 1a 25 26 27 28 29 2a 34 35 36 37 38 39 3a 43 44 45 46 47 48 49 4a 53 54 55 56 57 58 59 5a 63 64 65 66 67 68 69 6a 73 74 75 76 77 78 79 7a 83 84 85 86 87 88 89 8a 92 93 94 95 96 97 98 99 9a a2 a3 a4 a5 a6 a7 a8 a9 aa b2 b3 b4 b5 b6 b7 b8 b9 ba c2 c3 c4 c5 c6 c7 c8 c9 ca d2 d3 d4 d5 d6 d7 d8 d9 da e1 e2 e3 e4 e5 e6 e7 e8 e9 ea f1 f2 f3 f4 f5 f6 f7 f8 f9 fa ff c4 00 1f 01 00 03 01 01 01 01 01 01 01 01 01 00 00 00 00 00 00 01 02 03 04 05 06 07 08 09 0a 0b ff c4 00 b5 11 00 02 01 02 04 04 03 04 07 05 04 04 00 01 02 77 00 01 02 03 11 04 05 21 31 06 12 41 51 07 61 71 13 22 32 81 08 14 42 91 a1 b1 c1 09 23 33 52 f0 15 62 72 d1 0a 16 24 34 e1 25 f1 17 18 19 1a 26 27 28 29 2a 35 36 37 38 39 3a 43 44 45 46 47 48 49 4a 53 54 55 56 57 58 59 5a 63 64 65 66 67 68 69 6a 73 74 75 76 77 78 79 7a 82 83 84 85 86 87 88 89 8a 92 93 94 95 96 97 98 99 9a a2 a3 a4 a5 a6 a7 a8 a9 aa b2 b3 b4 b5 b6 b7 b8 b9 ba c2 c3 c4 c5 c6 c7 c8 c9 ca d2 d3 d4 d5 d6 d7 d8 d9 da e2 e3 e4 e5 e6 e7 e8 e9 ea f2 f3 f4 f5 f6 f7 f8 f9 fa ff da 00 0c 03 01 00 02 11 03 11 00 3f 00 f7 fa [1328] 0f 5a 3e d0 3d 68 02 cd 15 5b ed 03 d6 8f b4 0f 5a 00 b3 45 56 fb 40 f5 a3 ed 03 d6 80 2c d1 55 be d0 3d 68 fb 40 f5 a0 0b 34 55 6f b4 0f 5a 3e d0 3d 68 02 cd 15 5b ed 03 d6 8f b4 0f 5a 00 b3 45 56 fb 40 f5 a3 ed 03 d6 80 2c d1 55 be d0 3d 68 fb 40 f5 }
		$img_2  = { ff c2 00 0b 08 05 59 0b a9 01 01 11 00 ff c4 00 1c 00 01 00 02 03 01 01 01 00 00 00 00 00 00 00 00 00 00 05 07 03 04 06 02 01 08 ff da 00 08 01 01 00 00 00 01 ec 2f [5400] 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 02 86 be 40 00 00 00 00 00 ae 79 38 cb 4a b5 b1 3b 92 96 9f c3 5e dc d5 6f 19 da d8 fc 0f 35 1f d6 ec c1 6f 5a 55 4e c7 7d c6 f6 fc f7 21 bf 9e 52 cf a5 2e fe 27 97 d4 d4 ec b5 bc ce 57 3e 71 6d }
		$img_3  = { ff c0 00 11 08 03 18 02 64 03 01 22 00 02 11 01 03 11 01 ff c4 00 1f 00 00 01 05 01 01 01 01 01 01 00 00 00 00 00 00 00 00 01 02 03 04 05 06 07 08 09 0a 0b ff c4 00 b5 10 00 02 01 03 03 02 04 03 05 05 04 04 00 00 01 7d 01 02 03 00 04 11 05 12 21 31 41 06 13 51 61 07 22 71 14 32 81 91 a1 08 23 42 b1 c1 15 52 d1 f0 24 33 62 72 82 09 0a 16 17 18 19 1a 25 26 27 28 29 2a 34 35 36 37 38 39 3a 43 44 45 46 47 48 49 4a 53 54 55 56 57 58 59 5a 63 64 65 66 67 68 69 6a 73 74 75 76 77 78 79 7a 83 84 85 86 87 88 89 8a 92 93 94 95 96 97 98 99 9a a2 a3 a4 a5 a6 a7 a8 a9 aa b2 b3 b4 b5 b6 b7 b8 b9 ba c2 c3 c4 c5 c6 c7 c8 c9 ca d2 d3 d4 d5 d6 d7 d8 d9 da e1 e2 e3 e4 e5 e6 e7 e8 e9 ea f1 f2 f3 f4 f5 f6 f7 f8 f9 fa ff c4 00 1f 01 00 03 01 01 01 01 01 01 01 01 01 00 00 00 00 00 00 01 02 03 04 05 06 07 08 09 0a 0b ff c4 00 b5 11 00 02 01 02 04 04 03 04 07 05 04 04 00 01 02 77 00 01 02 03 11 04 05 21 31 06 12 41 51 07 61 71 13 22 32 81 08 14 42 91 a1 b1 c1 09 23 33 52 f0 15 62 72 d1 0a 16 24 34 e1 25 f1 17 18 19 1a 26 27 28 29 2a 35 36 37 38 39 3a 43 44 45 46 47 48 49 4a 53 54 55 56 57 58 59 5a 63 64 65 66 67 68 69 6a 73 74 75 76 77 78 79 7a 82 83 84 85 86 87 88 89 8a 92 93 94 95 96 97 98 99 9a a2 a3 a4 a5 a6 a7 a8 a9 aa b2 b3 b4 b5 b6 b7 b8 b9 ba c2 c3 c4 c5 c6 c7 c8 c9 ca d2 d3 d4 d5 d6 d7 d8 d9 da e2 e3 e4 e5 e6 e7 e8 e9 ea f2 f3 f4 f5 f6 f7 f8 f9 fa ff da 00 0c 03 01 00 02 11 03 11 00 3f 00 f7 fa [936] 28 a6 97 02 80 1d 45 47 e6 af ad 2f 98 a7 bd 00 3e 8a 6e f1 49 e6 2f ad 00 3e 8a 67 98 be b4 79 82 80 1f 45 33 cc 1e b4 9e 72 fa d0 04 94 54 7e 6a fa d2 f9 8b eb 40 0f a2 99 e6 0f 5a 3c c1 eb 40 0f a2 99 e6 2f ad 1e 62 fa d0 03 e8 a6 79 ab eb 47 98 28 }
	condition:
		$header at 0 and any of ($img_*)
}

rule enc_pdf_image_sizes {
	meta:
		author      = "kyle eaton"
		date        = "2026-05-26"
		description = "matches PDF image sizes that correlate with the images used in an encrypted PDF lure"
	strings:
		$header = { 25 50 44 46 2D 31 2E }
		$img1   = { 2F 49 6D 61 67 65 20 2F 57 69 64 74 68 20 32 30 32 20 2F 48 65 69 67 68 74 20 32 34 36 }
		$img2   = { 2F 49 6D 61 67 65 20 2F 57 69 64 74 68 20 31 32 33 20 2F 48 65 69 67 68 74 20 33 32 }
	condition:
		$header at 0
		and all of ($img*)
		and @img1 < @img2
}

rule w9_pdf_service_agreement_img_objects {
	meta:
		author      = "kyle eaton"
		date        = "2026-05-27"
		description = "matching the observed service agreements used in a subset of w9 pdfs"
	strings:
		$header             = { 25 50 44 46 2D 31 2E }
		$image_object       = { 2F 49 6D 61 67 65 0A 2F 57 69 64 74 68 20 35 37 32 0A 2F 48 65 69 67 68 74 20 31 35 35 0A }
		$image_stream_bytes = { 8B 1C 37 2A FA CE 08 E2 11 51 EB 0E }
	condition:
		$header at 0
		and all of them
}

rule adobe_sign_lure_banner_images {
	meta:
		author      = "brandon murphy"
		date        = "2026-06-01"
		description = "mathces on observed width/height of abused adobe sign header/footer in a PDF"
    strings:
        $hdr = /\/Subtype[ ]?\/Image[^>]{0,80}\/Width[ ]?(1119|1120|1121)[ ]?\/Height[ ]?(372|373|374)/
        $ftr = /\/Subtype[ ]?\/Image[^>]{0,80}\/Width[ ]?(1063|1064|1065)[ ]?\/Height[ ]?(340|341|342)/
    condition:
        uint32(0) == 0x46445025 and  // "%PDF"
        $hdr and $ftr
}

rule pdf_lure_image_blurry {
	meta:
		author      = "kyle eaton"
		date        = "2026-06-02"
		description = "Matches the image lure within some PDF phishing documents."
	strings:
		$header = { 25 50 44 46 2D 31 2E }
		$img_01 = { A0 02 8A 28 CD 00 14 51 9A 33 40 05 14 66 93 34 00 B4 52 66 8C D0 02 D1 49 9A 33 40 0B 45 19 A3 34 00 51 46 68 A0 02 8A 28 A0 02 8A 28 A0 02 8A }
	condition:
		$header at 0
		and $img_01
}

rule pdf_eCheckLure_format {
	meta:
		author      = "kyle eaton"
		date        = "2026-06-03"
		description = "Matching patterns used in the eCheckRun lures, including link rects and text content."
	strings:
		$header = { 25 50 44 46 2D 31 2E }
		$rect1   = { 2F 54 79 70 65 20 2F 41 6E 6E 6F 74 0A 2F 53 75 62 74 79 70 65 20 2F 4C 69 6E 6B 0A 2F 52 65 63 74 20 5B 20 32 30 36 2E 32 35 20 33 39 34 2E 32 35 20 33 38 38 2E 35 20 34 33 39 2E 32 35 20 5D 0A }
		$rect2   = { 2F 52 65 63 74 20 5B 20 34 34 2E 32 35 20 35 36 30 2E 37 35 20 32 36 34 2E 37 35 20 35 39 32 2E 32 35 20 5D }
		$t1  = { 5B 3C 30 30 35 32 3E 20 3C 30 30 36 35 3E 20 3C 30 30 37 36 3E 20 3C 30 30 36 39 3E 20 3C 30 30 37 37 3E 20 3C 30 30 32 30 3E 20 3C 30 30 34 44 3E 20 3C 30 30 37 33 3E 20 3C 30 30 36 31 3E 20 3C 30 30 36 37 3E 20 5D }
		$t2  = { 5B 3C 30 30 34 46 3E 20 3C 30 30 37 30 3E 20 3C 30 30 36 35 3E 20 3C 30 30 36 45 3E 20 3C 30 30 32 30 3E 20 3C 30 30 35 33 3E 20 3C 30 30 36 33 3E 20 3C 30 30 37 35 3E 20 3C 30 30 37 32 3E 20 3C 30 30 35 30 3E 20 3C 30 30 36 31 3E 20 3C 30 30 37 39 3E 20 3C 30 30 36 44 3E 20 3C 30 30 37 34 3E 20 3C 30 30 34 45 3E 20 3C 30 30 36 46 3E 20 3C 30 30 36 39 3E 20 5D }
	condition:
		$header at 0
		and ($rect1 or $rect2 or $t1 or $t2)
}

rule pdf_encrypted_cred_phish_001 {
	meta:
		author      = "kyle eaton"
		date        = "2026-06-04"
		description = "Matching the image size and other parameters for an encrypted PDF leading to cred phishing."
	strings:
		$header   = { 25 50 44 46 2D 31 2E }
		$img_size = { 2F 49 6D 61 67 65 0A 2F 57 69 64 74 68 20 31 30 31 38 0A 2F 48 65 69 67 68 74 20 31 31 32 32 }
	condition:
		$header at 0
		and $img_size
}

rule pdf_fake_invoice_image_font_sizes {
	meta:
		author      = "kyle eaton"
		date        = "06.08.2026"
		description = "matches pdfs with specific image width/height values and font width array"
	strings:
		$header           = { 25 50 44 46 2D 31 2E }
		$font_width_array = { 5B 20 32 37 38 20 30 20 30 20 30 20 30 20 30 20 30 20 30 20 30 20 30 20 30 20 30 20 30 20 33 33 33 20 30 20 30 20 35 35 36 20 35 35 36 20 35 35 36 20 35 35 36 20 35 35 36 20 35 35 36 20 35 35 36 20 30 20 30 20 30 20 30 20 30 20 30 20 30 20 30 20 30 20 30 20 37 32 32 20 37 32 32 20 37 32 32 20 37 32 32 20 36 36 37 20 36 31 31 20 30 20 30 20 32 37 38 20 30 20 37 32 32 20 30 20 38 33 33 20 37 32 32 20 37 37 38 20 36 36 37 20 30 20 37 32 32 20 36 36 37 20 36 31 31 20 37 32 32 20 30 20 30 20 30 20 30 20 30 20 30 20 30 20 30 20 30 20 30 20 30 20 35 35 36 20 30 20 30 20 36 31 31 20 35 35 36 20 30 20 36 31 31 20 36 31 31 20 32 37 38 20 30 20 35 35 36 20 32 37 38 20 30 20 36 31 31 20 36 31 31 20 30 20 30 20 33 38 39 20 35 35 36 20 33 33 33 20 36 31 31 5D }
		$image_size       = { 2F 54 79 70 65 2F 58 4F 62 6A 65 63 74 2F 53 75 62 74 79 70 65 2F 49 6D 61 67 65 2F 57 69 64 74 68 20 34 38 39 2F 48 65 69 67 68 74 20 31 34 31 }
	condition:
		$header at 0
		and $font_width_array and $image_size
}

rule fake_invoice_pdf_images_01 {
	meta:
		author      = "kyle eaton"
		date        = "2026-06-15"
		description = "matches PDFs with a specific email icon as part of the lure."
	strings:
		$header    = { 25 50 44 46 2D 31 2E }
		$email_jpg = { 00 00 00 00 00 02 39 DA 7E D0 F5 8E 8A FE DD 05 86 2B 9D 8D 70 8B 5A D9 9E D7 44 E5 E5 33 11 8E }
	condition:
		$header at 0 and
		$email_jpg
}

rule fake_invoice_pdf_structure_01 {
	meta:
		author      = "kyle eaton"
		date        = "2026-06-15"
		description = "matches PDFs with a specific link sizes and structure overlaps."
	strings:
		$header = { 25 50 44 46 2D 31 2E }
		$rect1  = { 2F 52 65 63 74 20 5B 33 34 37 2E 32 32 30 35 20 31 39 39 2E 35 36 38 37 20 35 31 34 2E 34 31 33 30 20 32 33 34 2E 31 37 39 37 5D }
	condition:
		$header at 0 and
		$rect1
}

rule w9_c001_signatures {
	meta:
		author      = "kyle eaton"
		date        = "2026-06-24"
		description = "matching re-used signature bytes observed in multiple fake w9 documents"
	strings:
		$header = { 25 50 44 46 2D 31 2E }
		$sig1   = { 2F 49 6D 61 67 65 0A 2F 57 69 64 74 68 20 32 39 31 0A 2F 48 65 69 67 68 74 20 31 33 38 0A 2F 43 6F 6C 6F 72 53 70 61 63 65 20 2F 44 65 76 69 63 65 47 72 61 79 0A 2F 42 69 74 73 50 65 72 43 6F 6D 70 6F 6E 65 6E 74 20 38 0A 2F 46 69 6C 74 65 72 20 2F 46 6C 61 74 65 44 65 63 6F 64 65 0A 2F 4C 65 6E 67 74 68 20 32 31 31 30 3E 3E 20 73 74 72 65 61 6D 0A 78 9C ED 9C CD 6B 1B C7 1B C7 87 39 E8 AE 9B 0E 31 39 D9 02 09 91 4B 0D F9 0F 84 17 4B C7 1E 4A AE A9 11 C4 92 31 B9 04 7A B4 31 AD C9 0B 2B E7 0F C8 25 C6 26 09 2D 96 2C A1 DF A9 39 E4 87 49 E3 46 2E 2B 92 A2 53 7B EB A1 E4 50 84 66 76 E7 AB 76 76 F5 B6 7A 8F 63 79 }
		$sig2   = { 2F 49 6D 61 67 65 0A 2F 57 69 64 74 68 20 33 36 33 0A 2F 48 65 69 67 68 74 20 31 34 30 0A 2F 43 6F 6C 6F 72 53 70 61 63 65 20 2F 44 65 76 69 63 65 47 72 61 79 0A 2F 42 69 74 73 50 65 72 43 6F 6D 70 6F 6E 65 6E 74 20 38 0A 2F 46 69 6C 74 65 72 20 2F 46 6C 61 74 65 44 65 63 6F 64 65 0A 2F 4C 65 6E 67 74 68 20 33 39 38 31 3E 3E 20 73 74 72 65 61 6D 0A 78 9C ED 9D 7D 7C 14 C5 19 C7 37 C9 5D 12 92 90 40 08 41 2A BE A0 88 28 84 20 60 5B 25 80 48 D5 6A D5 2A D6 6A 0A 42 A5 7E C4 56 C0 B6 58 4B 2D 88 20 2F 96 8A 54 C1 37 A8 EF 82 55 AB 58 45 AA 58 05 3E 80 A8 A0 C8 A7 80 F1 03 0A D6 50 90 08 88 90 E4 EE 76 F7 F9 D5 }
		$sig3   = { 2F 49 6D 61 67 65 0A 2F 57 69 64 74 68 20 33 36 30 0A 2F 48 65 69 67 68 74 20 38 38 0A 2F 43 6F 6C 6F 72 53 70 61 63 65 20 5B 2F 49 43 43 42 61 73 65 64 20 39 20 30 20 52 5D 0A 2F 53 4D 61 73 6B 20 38 20 30 20 52 0A 2F 42 69 74 73 50 65 72 43 6F 6D 70 6F 6E 65 6E 74 20 38 0A 2F 46 69 6C 74 65 72 20 2F 46 6C 61 74 65 44 65 63 6F 64 65 0A 2F 4C 65 6E 67 74 68 20 36 34 38 36 3E 3E 20 73 74 72 65 61 6D 0A 78 9C ED 5D D9 73 DA 48 B7 67 47 48 68 97 D0 82 D8 C1 C6 18 DB 38 8E B7 C9 66 27 13 67 96 4C 5E BE 4A CD CB E4 35 55 B7 E6 FB FF 9F 6F 5D 7E 95 BE 5D DD 92 10 18 5B 38 EE DF 43 2A 16 A8 39 EA }
	condition:
		$header at 0 and any of ($sig*)
}

rule w9_c001_structure {
	meta:
		author      = "kyle eaton"
		date        = "2026-06-24"
		description = "repeated object parameters observed in fake w9 documents"
	strings:
		$header = { 25 50 44 46 2D 31 2E }
		$obj_7  = { 37 20 30 20 6F 62 6A 0A 3C 3C 2F 54 79 70 65 20 2F 58 4F 62 6A 65 63 74 0A 2F 53 75 62 74 79 70 65 20 2F 49 6D 61 67 65 0A }
		$obj_8  = { 0A 37 20 30 20 6F 62 6A 0A 3C 3C 2F 54 79 70 65 20 2F 58 4F 62 6A 65 63 74 0A 2F 53 75 62 74 79 70 65 20 2F 49 6D 61 67 65 0A }
		$lw_1   = { 3C 3C 2F 43 41 20 31 0A 2F 63 61 20 31 0A 2F 4C 43 20 30 0A 2F 4C 4A 20 30 0A 2F 4C 57 20 31 2E 35 32 36 39 39 39 39 35 0A 2F 4D 4C 20 31 30 0A 2F 53 41 20 74 72 75 65 0A 2F 42 4D 20 2F 4E 6F 72 6D 61 6C 3E 3E }
		$lw_2   = { 3C 3C 2F 43 41 20 31 0A 2F 63 61 20 31 0A 2F 4C 43 20 30 0A 2F 4C 4A 20 30 0A 2F 4C 57 20 2E 37 36 33 30 30 30 30 31 0A 2F 4D 4C 20 31 30 0A 2F 53 41 20 74 72 75 65 0A 2F 42 4D 20 2F 4E 6F 72 6D 61 6C 3E 3E }
		$lw_3   = { 3C 3C 2F 43 41 20 31 0A 2F 63 61 20 31 0A 2F 4C 43 20 30 0A 2F 4C 4A 20 30 0A 2F 4C 57 20 31 2E 31 34 34 39 39 39 39 38 0A 2F 4D 4C 20 31 30 0A 2F 53 41 20 74 72 75 65 0A 2F 42 4D 20 2F 4E 6F 72 6D 61 6C 3E 3E }
	condition:
		$header at 0
		and all of ($obj_*)
		and all of ($lw_*)
}

rule pdf_quote_lure_01 {
	meta:
		author      = "kyle eaton"
		date        = "2026-06-29"
		description = "Matches the rect value associated with a 'quote' themed PDF lure. All of the samples so far have been the same other than a modified date/time in the metadata."
	strings:
		$header = { 25 50 44 46 2D 31 2E }
		$rect   = { 2F 52 65 63 74 20 5B 32 33 30 2E 33 34 35 32 38 20 34 }
	condition:
		$header at 0 and $rect
}

rule pdf_w9_signature_c003 {
	meta:
		author      = "kyle eaton"
		date        = "2026-06-29"
		description = "matching on signature re-use in this set of fake w9 activity"
	strings:
		$header = { 25 50 44 46 2D 31 2E }
		$sig_1  = { 02 80 0A 00 28 00 A0 0A D6 57 B6 9A 8D AC 17 B6 37 30 DD DA 5C A0 92 0B 88 1D 64 8A 54 27 19 56 52 46 43 02 AC BF 79 1D 4A 30 0C 08 50 0B 34 00 50 07 C3 BF B6 67 FC 14 5F F6 46 FD 83 3C 3B 69 AD 7E D1 7F 16 F4 3F 0C EB 5A A1 03 C3 3F 0D B4 }
	condition:
		$header at 0 and any of ($sig_*)
}