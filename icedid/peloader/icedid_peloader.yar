rule icedid_peloader {
	meta:
		description = "Hardcoded strings within the unpacked IcedID peloader"
		author = "Myrtus0x0"
		date = "2021-05-15"

	strings:
		$sadl_filename= "sadl_64.dll" ascii wide fullword

	condition:
		uint16(0) == 0x5A4D and all of them
}