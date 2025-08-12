rule WinRAR_CVE_2025_8088 {
      meta:
          description = "Rule matching CVE-2025-8088 via RAR5 STM service header ADS traversal"
          author = "Sublime Security"
          reference_1 = "https://www.welivesecurity.com/en/eset-research/update-winrar-tools-now-romcom-and-others-exploiting-zero-day-vulnerability/"
          reference_2 = "https://www.rarlab.com/technote.htm" 

      strings:
          // RAR5 signature
          $rar5 = { 52 61 72 21 1A 07 01 00 }

          // Complete STM service header pattern with SERVICE_DATA record type
          // 03 = HeadType 3 (SERVICE block)
          // [5-100] = Header fields (HeadFlags, ExtraSize, DataSize, FileFlags, etc.) - vint encoded
          // 03 = NameLength 3 (vint encoded)
          // 53 54 4D = Name "STM" (3 bytes)
          // [5-50] = Records structure overhead + record size field (vint encoded)
          // 07 = Record Type 7 (SERVICE_DATA) - this contains the actual ADS data
          $stm_with_service_data = { 03 [5-100] 03 53 54 4D [5-50] 07 }

          // ADS traversal patterns in the SERVICE_DATA record
          $ads_traversal1 = /:[\\\/]\.+[\\\/](\.\.[\\\/]){3,}/    // :.\..\..\.. pattern
          $ads_traversal2 = /:[\\\/](\.\.[\\\/]){4,}/             // :..\..\..\.. pattern
          $ads_env_var = /:%[A-Z_]+%[\\\/]/                       // :%WINDIR%\ pattern

      condition:
          // Must be a RAR5 archive with multiple STM+SERVICE_DATA patterns and ADS traversal
          $rar5 at 0 and
          #stm_with_service_data >= 3 and
          any of ($ads_*)
  }
