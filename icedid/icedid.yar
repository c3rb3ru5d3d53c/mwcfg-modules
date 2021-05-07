rule icedid
{
  strings:
      $amazon = "aws.amazon.com" nocase wide ascii
      $gadsCookie = "Cookie: __gads=" nocase wide ascii
      $obfuscationCode = {8A 44 11 ?? 32 04 11 88 44 0D 07 48 FF C1 48 83 F9 ??}
  condition:
      all of them
}