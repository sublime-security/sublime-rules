rule Phishing_PDF_Split_QR_Code_Pair_330
{
  meta:
      author = "brandon murphy"
      date = "2026-04-09"
      updated = "2026-04-10"
      description = "PDF containing two 165x330 JPEG images — a vertically split QR code pair"
  strings:
      $header = {25 50 44 46 2d 31 2e}
      // --- PDF object layer ---
      // Image XObject definitions for the QR halves.
      // Both objects declare the same dimensions + JPEG filter.
      $w = "/Width 165"
      $h = "/Height 330"
      $jpeg_filter = "/Filter /DCTDecode"
      $xobj_image = "/Subtype /Image"
      // --- JPEG layer ---
      // SOF0 (baseline) marker encoding exactly 165x330:
      //   ff c0       = SOF0 marker
      //   00 11       = segment length (17 bytes)
      //   08          = 8-bit precision
      //   01 4a       = height 330
      //   00 a5       = width 165
      //   03          = 3 components (YCbCr)
      $sof0 = {ff c0 00 11 08 01 4a 00 a5 03}
  condition:
      $header at 0 and
      // Both are JPEG XObject images
      $jpeg_filter and
      $xobj_image and
      // Exactly two QR-half image objects in the PDF
      #sof0 == 2 and
      #w == 2 and
      #h == 2 and
      // The two JPEG SOF0 markers appear within 100KB of each other
      @sof0[2] - @sof0[1] < 102400
}
rule Phishing_PDF_Split_QR_Code_Pair_290
{
  meta:
      author = "brandon murphy"
      date = "2026-04-10"
      description = "PDF containing two 145x290 JPEG images — a vertically split QR code pair"
  strings:
      $header = {25 50 44 46 2d 31 2e}
      // --- PDF object layer ---
      // Image XObject definitions for the QR halves.
      // Both objects declare the same dimensions + JPEG filter.
      $w = "/Width 145"
      $h = "/Height 290"
      $jpeg_filter = "/Filter /DCTDecode"
      $xobj_image = "/Subtype /Image"
      // --- JPEG layer ---
      // SOF0 (baseline) marker encoding exactly 145x290:
      //   ff c0       = SOF0 marker
      //   00 11       = segment length (17 bytes)
      //   08          = 8-bit precision
      //   01 22       = height 290
      //   00 91       = width 145
      //   03          = 3 components (YCbCr)
      $sof0 = {ff c0 00 11 08 01 22 00 91 03}
  condition:
      $header at 0 and
      // Both are JPEG XObject images
      $jpeg_filter and
      $xobj_image and
      // Exactly two QR-half image objects in the PDF
      #sof0 == 2 and
      #w == 2 and
      #h == 2 and
      // The two JPEG SOF0 markers appear within 100KB of each other
      @sof0[2] - @sof0[1] < 102400
}
rule Phishing_PDF_Split_QR_Code_Pair_370
{
    meta:
        author = "brandon murphy"
        date = "2026-04-10"
        description = "PDF containing two 185x370 JPEG images — a vertically split QR code pair"
    strings:
        $header = {25 50 44 46 2d 31 2e}
        // --- PDF object layer ---
        // Image XObject definitions for the QR halves.
        // Both objects declare the same dimensions + JPEG filter.
        $w = "/Width 185"
        $h = "/Height 370"
        $jpeg_filter = "/Filter /DCTDecode"
        $xobj_image = "/Subtype /Image"
        // --- JPEG layer ---
        // SOF0 (baseline) marker encoding exactly 185x370:
        //   ff c0       = SOF0 marker
        //   00 11       = segment length (17 bytes)
        //   08          = 8-bit precision
        //   01 72       = height 370
        //   00 b9       = width 185
        //   03          = 3 components (YCbCr)
        $sof0 = {ff c0 00 11 08 01 72 00 b9 03}
    condition:
        $header at 0 and
        // Both are JPEG XObject images
        $jpeg_filter and
        $xobj_image and
        // Exactly two QR-half image objects in the PDF
        #sof0 == 2 and
        #w == 2 and
        #h == 2 and
        // The two JPEG SOF0 markers appear within 100KB of each other
        @sof0[2] - @sof0[1] < 102400
}
rule Phishing_PDF_Split_QR_Code_Pair_410
{
    meta:
        author = "brandon murphy"
        date = "2026-04-22"
        description = "PDF containing two 205x410 JPEG images — a vertically split QR code pair"
    strings:
        $header = {25 50 44 46 2d 31 2e}
        // --- PDF object layer ---
        // Image XObject definitions for the QR halves.
        // Both objects declare the same dimensions + JPEG filter.
        $w = "/Width 205"
        $h = "/Height 410"
        $jpeg_filter = "/Filter /DCTDecode"
        $xobj_image = "/Subtype /Image"
        // --- JPEG layer ---
        // SOF0 (baseline) marker encoding exactly 205x410:
        //   ff c0       = SOF0 marker
        //   00 11       = segment length (17 bytes)
        //   08          = 8-bit precision
        //   01 9a       = height 410
        //   00 cd       = width 205
        //   03          = 3 components (YCbCr)
        $sof0 = {ff c0 00 11 08 01 9a 00 cd 03}
    condition:
        $header at 0 and
        // Both are JPEG XObject images
        $jpeg_filter and
        $xobj_image and
        // Exactly two QR-half image objects in the PDF
        #sof0 == 2 and
        #w == 2 and
        #h == 2 and
        // The two JPEG SOF0 markers appear within 100KB of each other
        @sof0[2] - @sof0[1] < 102400
}
rule Phishing_PDF_Split_QR_Code_Pair_450
{
    meta:
        author = "brandon murphy"
        date = "2026-04-22"
        description = "PDF containing two 225x450 JPEG images — a vertically split QR code pair"
    strings:
        $header = {25 50 44 46 2d 31 2e}
        // --- PDF object layer ---
        // Image XObject definitions for the QR halves.
        // Both objects declare the same dimensions + JPEG filter.
        $w = "/Width 225"
        $h = "/Height 450"
        $jpeg_filter = "/Filter /DCTDecode"
        $xobj_image = "/Subtype /Image"
        // --- JPEG layer ---
        // SOF0 (baseline) marker encoding exactly 225x450:
        //   ff c0       = SOF0 marker
        //   00 11       = segment length (17 bytes)
        //   08          = 8-bit precision
        //   01 c2       = height 450
        //   00 e1       = width 225
        //   03          = 3 components (YCbCr)
        $sof0 = {ff c0 00 11 08 01 c2 00 e1 03}
    condition:
        $header at 0 and
        // Both are JPEG XObject images
        $jpeg_filter and
        $xobj_image and
        // Exactly two QR-half image objects in the PDF
        #sof0 == 2 and
        #w == 2 and
        #h == 2 and
        // The two JPEG SOF0 markers appear within 100KB of each other
        @sof0[2] - @sof0[1] < 102400
}
rule Phishing_PDF_Split_QR_Code_Pair_490
{
    meta:
        author = "brandon murphy"
        date = "2026-04-22"
        description = "PDF containing two 245x490 JPEG images — a vertically split QR code pair"
    strings:
        $header = {25 50 44 46 2d 31 2e}
        // --- PDF object layer ---
        // Image XObject definitions for the QR halves.
        // Both objects declare the same dimensions + JPEG filter.
        $w = "/Width 245"
        $h = "/Height 490"
        $jpeg_filter = "/Filter /DCTDecode"
        $xobj_image = "/Subtype /Image"
        // --- JPEG layer ---
        // SOF0 (baseline) marker encoding exactly 245x490:
        //   ff c0       = SOF0 marker
        //   00 11       = segment length (17 bytes)
        //   08          = 8-bit precision
        //   01 ea       = height 490
        //   00 f5       = width 245
        //   03          = 3 components (YCbCr)
        $sof0 = {ff c0 00 11 08 01 ea 00 f5 03}
    condition:
        $header at 0 and
        // Both are JPEG XObject images
        $jpeg_filter and
        $xobj_image and
        // Exactly two QR-half image objects in the PDF
        #sof0 == 2 and
        #w == 2 and
        #h == 2 and
        // The two JPEG SOF0 markers appear within 100KB of each other
        @sof0[2] - @sof0[1] < 102400
}
