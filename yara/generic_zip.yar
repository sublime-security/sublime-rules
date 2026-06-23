rule zipline_delivery_telekom {
	meta:
		author      = "kyle eaton"
		date        = "2026-06-18"
		description = "https://github.security.telekom.com/2026/06/ZipLine-linked-spearphishing-campaign.html"
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