rule WinRAR_CVE_2025_8088 {
      meta:
          description = "Rule matching CVE-2025-8088 via RAR5 STM service header ADS traversal"
          author = "Sublime Security"
          reference_1 = "https://www.welivesecurity.com/en/eset-research/update-winrar-tools-now-romcom-and-others-exploiting-zero-day-vulnerability/"
          reference_2 = "https://www.rarlab.com/technote.htm" 

      strings:
          // RAR5 signature
          $rar5 = { 52 61 72 21 1A 07 01 00 }

          // Service header (HeadType=3) with STM name
          $stm_service_header = { 03 [5-100] 03 53 54 4D }

          // ADS traversal patterns in service records
          $ads_traversal1 = /:[\\\/]\.+[\\\/](\.\.[\\\/]){3,}/
          $ads_traversal2 = /:[\\\/](\.\.[\\\/]){4,}/
          $ads_env_var = /:%[A-Z_]+%[\\\/]/

      condition:
          // Must be a RAR5 archive
          $rar5 at 0 and

          // Require multiple STM service headers (bulk ADS injection indicator)
          #stm_service_header >= 3 and

          // Reasonable file size limit to avoid performance issues
          filesize < 100MB and

          // For each STM service header found in the file
          for any i in (1..#stm_service_header): (
              // Check if any ADS traversal pattern occurs within 500 bytes after the STM header
              // This proximity check ensures the ADS data is actually within the service record
              for any of ($ads_*): (
                  // $ represents the current ADS pattern being checked
                  // @stm_service_header[i] is the file offset of the i-th STM header
                  // The range @stm_service_header[i]..@stm_service_header[i]+500 covers
                  // the STM header plus the following service record data area
                  $ in (@stm_service_header[i]..@stm_service_header[i]+500)
              )
          )
  }
