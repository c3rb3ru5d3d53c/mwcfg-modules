rule dynamicrat {
    meta:
        author      = "c3rb3ru5"
        description = "DynamicRAT"
        reference   = "https://gi7w0rm.medium.com/dynamicrat-a-full-fledged-java-rat-1a2dabb11694"
        hash        = "41a037f09bf41b5cb1ca453289e6ca961d61cd96eeefb1b5bbf153612396d919"
        type        = "malware.rat"
        created     = "2023-06-11"
        os          = "windows"
        tlp         = "white"
        rev         = 1
    strings:
        $string_0 = "dynamic/client/attack/AttackManager.class"
        $string_1 = "dynamic/core/model/RunningAttack.class"
        $manifest = "META-INF/MANIFEST"
    condition:
        (uint16(0) == 0x4b50 and $manifest) and
        all of them
}
