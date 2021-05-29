rule asyncrat {
    meta:
        author      = "c3rb3ru5"
        description = "ASyncRAT"
        hash        = "330493a1ba3c3903040c9542e6348fab"
        type        = "malware.rat"
        created     = "2021-05-29"
        os          = "windows"
        tlp         = "white"
        rev         = 1
    strings:
        $magic_cslr_0 = "BSJB"
        $salt         = {BF EB 1E 56 FB CD 97 3B B2 19 02 24 30 A5 78 43 00 3D 56 44 D2 1E 62 B9 D4 F1 80 E7 E6 C3 39 41}
    condition:
        uint16(0) == 0x5a4d and
        uint32(uint32(0x3c)) == 0x00004550 and
        filesize < 2605056 and
        all of them
}
