rule aes_encryption_keywords {
  meta:
    description = "Detects the use of AES Encryption keywords"
    author = "Sublime Security"
    severity = "low"
    reference = "AES-256-CBC with HMAC-SHA-256 implementation in MS Office files"
  
  strings:
    // AES Encryption indicators
    $aes1 = "AES-256-CBC" ascii wide nocase
    $aes2 = "HMAC-SHA-256" ascii wide nocase
    $aes3 = "RijndaelManaged" ascii wide
    $aes4 = "System.Security.Cryptography" ascii wide
    
    // Encryption functions and parameters
    $enc1 = "Encrypt" ascii wide
    $enc2 = "Decrypt" ascii wide
    $enc3 = "aesKey" ascii wide nocase
    $enc4 = "Base64" ascii wide nocase
    
    // VBScript implementation
    $vbs = "aes.vbs" ascii wide nocase
    
    // Crypto library fragments
    $crypto1 = "FromBase64Transform" ascii wide
    $crypto2 = "ToBase64Transform" ascii wide
    $crypto3 = "MemoryStream" ascii wide
    
  condition:
    // High confidence detection - specific AES implementation
    ($aes1 and $aes2) or
    
    // Medium confidence detection - crypto libraries with encryption functions
    ($aes3 and ($enc1 or $enc2)) or
    ($aes4 and ($enc1 or $enc2)) or
    
    // Lower confidence but specific patterns
    ($vbs and $aes1) or
    (2 of ($crypto*) and 1 of ($enc*) and $enc3 and $enc4)
}
