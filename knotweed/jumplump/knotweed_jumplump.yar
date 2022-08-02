rule knotweed_jumplump {
    meta:
        author      = "@c3rb3ru5d3d53c"
        description = "Knotweed Jumplump"
        hash        = "5d169e083faa73f2920c8593fb95f599dad93d34a6aa2b0f794be978e44c8206"
        created     = "2022-08-02"
        os          = "windows"
        tlp         = "white"
        rev         = 1
    strings:
        $pic_pattern = {E8 00 00 00 00 59 48 83 E9 05}
        $trait       = {48 a1 ?? ?? ?? ?? ?? ?? ?? ?? 50 b8 0? 00 00 00 c3}
    condition:
        uint16(0) == 0x5a4d and
        uint32(uint32(0x3c)) == 0x00004550 and
        all of them
}
