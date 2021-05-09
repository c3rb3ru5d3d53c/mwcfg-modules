rule icedid
{
  strings:
    $obfuscationCode = {8A 44 11 ?? 32 04 11 88 44 0D 07 48 FF C1 48 83 F9 ??}
    $amazon = "aws.amazon.com" nocase wide ascii
    $gadsCookie = "Cookie: __gads=" nocase wide ascii   
  condition:
    uint16(0) == 0x5a4d and filesize < 800KB and
    all of them
}