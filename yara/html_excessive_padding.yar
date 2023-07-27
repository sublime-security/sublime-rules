rule HTML_EXCESSIVE_PADDING {
    meta:
        author = "Aiden Mitchell"
        date = "2023-06-21"

    strings:
        $breaks = /(\r\n){150,}|\n{150,}/
        $js_pattern = { 5F 30 78 } // _0x

    condition:
        $breaks at 0 and #js_pattern >= 50
}
