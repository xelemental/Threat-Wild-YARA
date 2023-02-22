rule malware_rc4 {
    meta:
        author = "ElementalX"
        description = "Detects RC4 algorithm"
        reference = "https://en.wikipedia.org/wiki/RC4"
        sample = "revil.bin"
        sha256 = "329983dc2a23bd951b24780947cb9a6ae3fb80d5ef546e8538dfd9459b176483"
    strings:
        $s1 = { 8D 8D F0 FE FF FF 8B C2 03 CA 83 E0 1F 8A 04 38 88 14 0B 42 88 01 } //Initialize S-box array with values 0 to 255
        $s2 = { 8B 7D F0 8D B5 F0 FE FF FF 8B DF 2B F7 } //Perform Key Scheduling Algorithm to scramble S-Box 
        $s3 = { 8A 13 0F BE 04 1E 03 45 FC 0F B6 CA 03 C8 81 E1 FF 00 00 80 79 08 } // Generate key stream by looping through S-box and XORing with data
        $s4 = { 8A 04 39 88 03 43 83 6D F8 01 89 4D FC 88 14 39 } //Generate key stream by looping through S-box and XORing with data part 2 
    condition:
        uint16(0) == 0x5A4D and // Check if file is a PE file
        filesize < 1MB and      // Check if file size is less than 1 MB
        all of ($s*)            // Check if all strings exist in the file
} 
