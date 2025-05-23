rule encrypted_msaccess_database {
  meta:
    description = "Detects Microsoft Access Databases with AES Encryption"
    author = "Sublime Security"
    severity = "medium"
    reference = "AES-256-CBC with HMAC-SHA-256 VBScript implementation"
  
  strings:
    // MS Access file signature
    $access_sig = { 00 01 00 00 53 74 61 6E 64 61 72 64 20 41 43 45 20 44 42 }
    
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
    $access_sig at 0 and
    (
      // High confidence detection - specific AES implementation
      ($aes1 and $aes2) or
      
      // Medium confidence detection - crypto libraries with encryption functions
      ($aes3 and ($enc1 or $enc2)) or
      ($aes4 and ($enc1 or $enc2)) or
      
      // Lower confidence but specific patterns
      ($vbs and $aes1) or
      (2 of ($crypto*) and 1 of ($enc*) and $enc3 and $enc4)
    )
}
