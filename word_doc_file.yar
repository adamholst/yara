rule word_doc
{
	meta:
		description = "This is a POC to identify Microsoft Word documents."
		author = "Adm Holst"
		email = "AdamHolst@ProtonMail.com"
		
	strings:
		$s1 = "microsoft" // s1-3 are for 0 byte doc files
		$s2 = "office"
		$s3 = "word"
		$h1 = { D0 CF 11 E0 A1 B1 1A E1 } // .doc match
		$h2 = { 50 4B 03 04 } // matches both .doc and .docx
		$h3 = { 50 4B 05 06 } // same as h2
		$h4 = { 50 4B 07 08 } // zip format of .doc and .docx
		

	condition:
		any of them
}