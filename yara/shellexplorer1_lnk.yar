rule ShellExplorer1_LNK_OLE
{
    strings:
        $ole_magic = { D0 CF 11 E0 A1 B1 1A E1 }

        // Shell.Explorer.1 CLSID {EAB22AC3-30C1-11CF-A7EB-0000C05BAE0B} little-endian
        $clsid = { C3 2A B2 EA C1 30 CF 11 A7 EB 00 00 C0 5B AE 0B }

        // LNK header (first 8 bytes)
        $lnk = { 4C 00 00 00 01 14 02 00 }

    condition:
        $ole_magic at 0 and
        filesize < 10MB and
        $clsid and $lnk
}

rule ShellExplorer1_LNK_RTF
{
    strings:
        $rtf_magic = "{\\rt" ascii

        // Shell.Explorer.1 CLSID - hex-encoded (first 8 bytes)
        $clsid_hex = "c32ab2eac130cf11" ascii nocase
        // Shell.Explorer.1 CLSID - binary (for \bin or obfuscated RTF)
        $clsid_bin = { C3 2A B2 EA C1 30 CF 11 A7 EB 00 00 C0 5B AE 0B }

        // LNK header - hex-encoded (first 8 bytes)
        $lnk_hex = "4c00000001140200" ascii nocase
        // LNK header - binary
        $lnk_bin = { 4C 00 00 00 01 14 02 00 }

    condition:
        $rtf_magic at 0 and
        filesize < 5MB and
        (($clsid_hex or $clsid_bin) and ($lnk_hex or $lnk_bin))
}
