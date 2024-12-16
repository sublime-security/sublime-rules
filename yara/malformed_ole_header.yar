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
        $pk_start at 0 and
        
        // Must not start with any of the standard signatures
        not (
            uint32(0) == 0x04034B50 or  // PK\x03\x04 in little-endian
            uint32(0) == 0x06054B50 or  // PK\x05\x06 in little-endian
            uint32(0) == 0x08074B50     // PK\x07\x08 in little-endian
        ) and
        
        // Must contain normal PK signature somewhere after the start
        $normal_pk in (2..filesize)
}
