rule Detect_ASPACK_Packed_PE_File {
    meta:
        description = "Detects PE file packed with ASPACK"
        author = "ElementalX & Muffin"
        reference = "http://www.aspack.com/downloads.html"
        date = "2023-02-22"
    strings:
        $s1 = "\xAD\x85\xC0\x74\x40\x83\xC7\x28\x3B\x47\x0C\xE0\xF8\x75\x36\x41\x51\x56\x6A\x01"
        $s2 = "\xF6\x46\x07\xE0\x74\x03\xD1\x24\x24\xF6\x46\x07\x80\x74\x03\xD1\x24\x24\xF6\x46\x07\x20\x74\x04\xC1\x24\x24\x04"
    condition:
        uint16(0) == 0x5A4D and
        uint32(uint32(0x3C)) == 0x00004550 and
        all of them 
}
