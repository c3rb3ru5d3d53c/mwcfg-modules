rule zxxz {
	meta:
		author      = "c3rb3ru5d3d53c"
		description = "MALWARE Bitter APT ZxxZ Backdoor"
		hash        = "09bb6b01db8b2177779d90c5444d91859994a1c2e907e5b444d6f6e67d2cfcfe"
		reference   = "https://c3rb3ru5d3d53c.github.io"
		created     = "2022-07-01"
		os          = "windows"
		tlp         = "white"
		rev         = 1
	strings:
		$zxxz_delimiter        = "ZxxZ" ascii wide
		$zxxz_rng              = {c7 05 ?? ?? ?? ?? 52 4e 47 00}
		$zxxz_string_decryptor = {53 3b ca 75 ?? 33 c9 8a 1c ?? 30 1c ?? 40 41 3b c6 7c}
        $config_0              = {6a 6d 56 ff 15 ?? ?? ?? ?? 8d 44 ?? ?? 50 68 02 02 00 00 ff 15 ?? ?? ?? ?? 85 c0 0f 85}
	condition:
		uint16(0) == 0x5a4d and
        uint32(uint32(0x3c)) == 0x00004550 and
		filesize < 4128028 and
        2 of ($zxxz_*) and
		$config_0
}
