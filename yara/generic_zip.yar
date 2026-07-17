rule zipline_delivery_telekom {
	meta:
		author      = "kyle eaton"
		date        = "2026-06-18"
		ref = "https://github.security.telekom.com/2026/06/ZipLine-linked-spearphishing-campaign.html"
		description = "zip file with one double extension (docx.lnk) and two docx lures per the ref campaign"
	strings:
		$pklfh = { 50 4b 03 04 }
		$ext   = ".docx.lnk"
		$docx  = ".docx"
	condition:
		uint16be(0) == 0x504b and
		for any i in (1..100): (
			($ext in ((@pklfh[i] + 30 + uint16(@pklfh[i] + 26) - !ext)..(@pklfh[i] + 30 + uint16(@pklfh[i] + 26))))
		) and
		for 2 i in (1..100): (
			($docx in ((@pklfh[i] + 30 + uint16(@pklfh[i] + 26) - !docx)..(@pklfh[i] + 30 + uint16(@pklfh[i] + 26))))
		)
}

rule zip_smuggler_default {
	meta:
		author      = "kyle eaton"
		ref      = "https://github.com/Octoberfest7/zip_smuggling"
		date        = "2026-06-22"
		description = "zip file with the default 'egghunt' value 0x55555555 after the file bytes of a PKLFH. s/o @ffforward"
	strings:
		$pklfh = { 50 4b 03 04 }
		$ext   = ".lnk"
	condition:
		uint16be(0) == 0x504b
		and for any i in (1..100): (
			// extra field == 0
			uint16(@pklfh[i] + 28) == 0x00
			// UUUU after the file data
			and uint32be(@pklfh[i] + 30 + uint16(@pklfh[i] + 26) + uint32(@pklfh[i] + 18)) == 0x55555555
		)
		// need at least one LNK file 
		and for any i in (1..100): (
			($ext in ((@pklfh[i] + 30 + uint16(@pklfh[i] + 26) - !ext)..(@pklfh[i] + 30 + uint16(@pklfh[i] + 26))))
		)
}

rule zip_excel_dll {
	meta:
		author      = "kyle eaton"
		date        = "2026-07-16"
		description = "Matching zip files that include the CRC32 of a known excel binary and an unknown DLL"
	strings:
		$pklfh = { 50 4b 03 04 }
		$dll   = ".dll"
		$exe   = ".exe"
	condition:
		uint16be(0) == 0x504B and
		for any i in (1..100): (
			($dll in ((@pklfh[i] + 30 + uint16(@pklfh[i] + 26) - 4)..(@pklfh[i] + 30 + uint16(@pklfh[i] + 26))))
		) and
		for any i in (1..100): (
			($exe in ((@pklfh[i] + 30 + uint16(@pklfh[i] + 26) - 4)..(@pklfh[i] + 30 + uint16(@pklfh[i] + 26))))
			and uint32(@pklfh[i] + 14) == 0x420b8579
			and uint32(@pklfh[i] + 22) == 74719472
		)

}
