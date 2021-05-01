rule hancitor {
	meta:
		description = "URL arguments for Hancitor unpacked samples"
		author = "Myrtus0x0"
		date = "2021-05-01"

	strings:
		$url_args_64 = "GUID=%I64u&BUILD=%s&INFO=%s&EXT=%s&IP=%s&TYPE=1&WIN=%d.%d(x64)" ascii wide fullword
		$url_args_32 = "GUID=%I64u&BUILD=%s&INFO=%s&EXT=%s&IP=%s&TYPE=1&WIN=%d.%d(x32)" ascii wide fullword

	condition:
		uint16(0) == 0x5A4D and ($url_args_64 and $url_args_32)
}