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

rule zip_office_bin_dll {
	meta:
		author      = "kyle eaton"
		date        = "2026-07-16"
		updated     = "2026-08-19"
        description = "Matching zip files that include the crc32 and file size of a known office binary and an unknown DLL"
	strings:
		$pklfh = { 50 4b 03 04 }
		$dll   = ".dll"
		$exe   = ".exe"
	condition:
        uint16be(0) == 0x504b and
        for any i in (1..100): (
            ($dll in ((@pklfh[i] + 30 + uint16(@pklfh[i] + 26) - 4)..(@pklfh[i] + 30 + uint16(@pklfh[i] + 26))))
        ) and
        for any i in (1..100): (
            ($exe in ((@pklfh[i] + 30 + uint16(@pklfh[i] + 26) - 4)..(@pklfh[i] + 30 + uint16(@pklfh[i] + 26))))
            and (
                // win word
                (uint32(@pklfh[i] + 14) == 0xf863bd78 and uint32(@pklfh[i] + 22) == 1559784) or
                // excel
                (uint32(@pklfh[i] + 14) == 0x420b8579 and uint32(@pklfh[i] + 22) == 74719472)
            )
        )
}

rule zip_pklfh_cd_mismatch_fname {
    meta:
        author      = "kyle eaton"
        date        = "2026-08-18"
        description = "zip file with a mismatch file name between the local file header and the central directory entry"
    strings:
        $pklfh = { 50 4B 03 04 }
        $pkcd  = { 50 4B 01 02 }
    condition:
        for any i in (1..100): (
            uint16(@pklfh[i] + 26) < 100
            and for any j in (1..uint16(@pklfh[i] + 26)): (
                uint8(@pklfh[i] + 30 + j - 1) != uint8(@pkcd[i] + 46 + j - 1)
            )
        )
}