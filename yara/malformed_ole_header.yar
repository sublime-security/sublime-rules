rule MALFORMED_OLE_HEADER
{
    meta:
        description = "Detects files starting with PK but not PK\\x03\\x04, while containing PK\\x03\\x04 later in the file."
        author = "Aiden Mitchell"
        created = "2024-11-25"
        
    strings:
        $pk_start = { 50 4B }
        $normal_pk = { 50 4B 03 04 }
        
    condition:
        // File must start with PK but not PK\x03\x04
        uint16(0) == 0x4B50 and
        not (uint32(0) == 0x04034B50) and
        // PK\x03\x04 must appear somewhere after the start
        $normal_pk in (2..filesize)
}
