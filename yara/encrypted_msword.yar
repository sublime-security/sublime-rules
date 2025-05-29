rule Encrypted_Word_AES_Macro {
    meta:
        author = "Sublime Security"
        description = "Detects Microsoft Word documents containing AES-256-CBC encryption implementation in VBA macros"
        date = "2024-05-29"
        reference = "https://github.com/susam/aes.vbs/blob/a0cb5f9ffbd90b435622f5cfdb84264e1a319bf2/aes.vbs"

        
    strings:
        // Document markers
        $doc_marker = { D0 CF 11 E0 } // OLE document header
        $word_marker = "Word.Document.8" nocase
        
        // VBA Project markers
        $vba_marker = "VBA" nocase
        $module_marker = "Module=" nocase
        
        // AES-specific strings
        $aes_comment1 = "AES-256-CBC with HMAC-SHA-256" ascii wide
        $aes_comment2 = "Credit to https://github.com/susam/aes.vbs" ascii wide
        $aes_class1 = "System.Security.Cryptography.RijndaelManaged" ascii wide
        $aes_class2 = "System.Security.Cryptography.HMACSHA256" ascii wide
        
        // Crypto functions
        $func_encrypt = "Encrypt" ascii wide
        $func_decrypt = "Decrypt" ascii wide
        $func_generateiv = "GenerateIV" ascii wide
        
        // Base64 transformation indicators
        $base64_1 = "System.Security.Cryptography.ToBase64Transform" ascii wide
        $base64_2 = "System.Security.Cryptography.FromBase64Transform" ascii wide
        
        // AES properties
        $aes_prop1 = "aes.BlockSize" ascii wide
        $aes_prop2 = "aes.KeySize" ascii wide
        $aes_prop3 = "aes.Mode" ascii wide
        $aes_prop4 = "aes.Padding" ascii wide
        
    condition:
        $doc_marker at 0 and 
        $word_marker and 
        $vba_marker and 
        $module_marker and
        (
            // Must have at least one AES comment
            ($aes_comment1 or $aes_comment2) and
            // Must have at least one AES class
            ($aes_class1 or $aes_class2) and
            // Must have at least one encryption function
            ($func_encrypt or $func_decrypt or $func_generateiv) and
            // Must have at least one Base64 transformation
            ($base64_1 or $base64_2) and
            // Must have at least one AES property
            ($aes_prop1 or $aes_prop2 or $aes_prop3 or $aes_prop4)
        )
}
