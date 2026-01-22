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