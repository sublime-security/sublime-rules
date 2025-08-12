rule WinRAR_CVE_2025_8088 {
      meta:
          description = "Rule matching CVE-2025-8088 via RAR5 STM service header ADS traversal"
          author = "Sublime Security"
          reference_1 = "https://www.welivesecurity.com/en/eset-research/update-winrar-tools-now-romcom-and-others-exploiting-zero-day-vulnerability/"
          reference_2 = "https://www.rarlab.com/technote.htm" 

      strings:
          // RAR5 signature
          $rar5 = { 52 61 72 21 1A 07 01 00 }

          // STM service header + SERVICE_DATA record type 7
          $stm_with_service_data = { 03 [5-100] 03 53 54 4D [5-50] 07 }

          // ADS traversal patterns
          $ads_traversal1 = /:[\\\/]\.+[\\\/](\.\.[\\\/]){3,}/
          $ads_traversal2 = /:[\\\/](\.\.[\\\/]){4,}/
          $ads_env_var = /:%[A-Z_]+%[\\\/]/

      condition:
          $rar5 at 0 and
          #stm_with_service_data >= 3 and
          for any i in (1..#stm_with_service_data): (
              for any of ($ads_*): (
                  $ in (@stm_with_service_data[i]..@stm_with_service_data[i]+200)
              )
          )
  }
