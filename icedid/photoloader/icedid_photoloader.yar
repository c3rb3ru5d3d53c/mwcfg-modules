rule icedid_photoloader {
  meta:
      author      = "4rchib4ld"
      description = "IcedID PhotoLoader"
      hash        = "0321aea38c3eeae272549f306caaa97a"
      reference   = "https://4rchib4ld.github.io/blog/IcedIDOnMyNeckImTheCoolest/"
      type        = "malware.downloader"
      created     = "2021-05-10"
      os          = "windows"
      tlp         = "white"
      rev         = 1
  strings:
    $obfuscationCode = {8A 44 11 ?? 32 04 11 88 44 0D 07 48 FF C1 48 83 F9 ??}
    $s1       =  "_gat="   ascii wide
    $s2       = "_ga="    ascii wide
    $s3       = "_u="     ascii wide
    $s4       = "__io="   ascii wide
    $s5       = "_gid="   ascii wide
    $s6       = "__gads=" ascii wide
  condition:
    uint16(0) == 0x5a4d and filesize < 800KB and
    $obfuscationCode and 3 of ($s*)
}
