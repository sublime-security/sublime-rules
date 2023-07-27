rule SublimeStandardTestString {
   meta:
      author = "Sublime Security"
      description = "Used to test that Sublime Platform YARA signature support is working properly."

   strings:
      $test_string = "Sublime-Standard-Test-String"

   condition:
      $test_string at 0
}
