rule MSG_Props_Unsent_Flag
{
    meta:
        author = "Sublime Security"
        description = "Outlook message (MS-OXMSG) property stream with the unsent flag (MSGFLAG_UNSENT) set in PR_MESSAGE_FLAGS"
        reference = "https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxmsg/"
    strings:
        // PR_MESSAGE_FLAGS entry (0x0E07, PT_LONG): tag, 4 flag bytes, then a value byte with MSGFLAG_UNSENT (0x08) set
        $unsent = { 03 00 07 0E ?? ?? ?? ?? ( ?8 | ?9 | ?A | ?B | ?C | ?D | ?E | ?F ) }
    condition:
        // the stream starts with 8 reserved zero bytes
        filesize < 65536 and
        uint32(0) == 0 and uint32(4) == 0 and
        // entries are 16 bytes each, after a 32-byte (top level) or 24-byte (embedded) header
        @unsent[1] >= 24 and @unsent[1] % 8 == 0
}
