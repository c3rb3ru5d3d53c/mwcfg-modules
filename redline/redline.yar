rule redline {
    meta:
        author     = "@c3r3ru5d3d53c"
        descrption = "Redline Stealer"
        tlp        = "white"
    strings:
        $string_0 = "net.tcp://" ascii wide
        $bytecode_0 = {
            72 3D 09 00 70 80 03 00 00 04 72 7F 09 00 70
            80 04 00 00 04 72 99 09 00 70 80 05 00 00 04
            72 9B 09 00 70 80 06 00 00 04 17 80 07 00 00
            04 2A}
    condition:
        all of them
}
