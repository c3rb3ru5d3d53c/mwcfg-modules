rule darkcloud {
    meta:
        author = "@c3rb3ru5d3d53c"
        description = "DarkCloud Stealer"
    strings:
        $name_0 = "DarkCloud Keylogger" ascii wide
        $key_0  = {ba ?? ?? 40 00 8d 4?}
    condition:
        uint16(0) == 0x5A4D and
        all of them
}
