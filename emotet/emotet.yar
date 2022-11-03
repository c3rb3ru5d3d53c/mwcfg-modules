rule emotet {
    meta:
        author      = "t-mtsmt"
        description = "Emotet Configuration Extractor"
        hash        = "570222682c005a77dfd3f693c4a3d441"
        created     = "2022-11-02"
        os          = "windows"
        tlp         = "amber"
        rev         = 1
    strings:
        $ref_c2 = {
            c7 44 ?4 ?0 ?? ?? ?? ??     // MOV  dword ptr [RSP + 0x40],0x7ac76da7   ; ip address encrypted with xor
            c7 04 ?4 ?? ?? ?? ??        // MOV  dword ptr [RSP],0x7243d362          ; port encrypted with xor
            c7 44 ?4 ?8 ?? ?? ?? ??     // MOV  dword ptr [RSP + 0x38],0xc0b285c9   ; xor key for decrypting ip address
            c7 44 ?4 ?8 ?? ?? ?? ??     // MOV  dword ptr [RSP + 0x48],0x6dd3d363   ; xor key for decrypting port
        }
   condition:
        uint16(0) == 0x5A4D and all of them
}