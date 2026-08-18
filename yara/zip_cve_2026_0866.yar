rule zip_cve_2026_0866
{
    meta:
        author = "kyle eaton"
        description = "match zip files with STORE compression method that have mismatched compressed/uncompressed sizes. CVE-2026-0866"
        reference = "https://github.com/bombadil-systems/zombie-zip"
    strings:
        $pklfh = {50 4b 03 04}
        $pkeocd = {50 4b 05 06}
    condition:
        uint32be(0) == 0x504b0304 and
        #pkeocd == 1 and 
        // all files should be STORE compression method
        for all i in (1 .. #pklfh) : (
            uint8be(@pklfh[i] + 8) == 0x00 and
            // no pw flag -  thx greg
            uint16(@pklfh[i] + 6) & 0x01 != 1 and 
            // uncompressed size != compressed size
            uint32be(@pklfh[i] + 18) != uint32be(@pklfh[i] + 22)
        )
}
