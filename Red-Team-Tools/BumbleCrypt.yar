rule bumble_crypt {
    meta:
       author = "Elemental X"
       description = "Yara rule for detecting Crypter inspired by BumbleBee"
       link = "hxxps://github.com/knight0x07/BumbleCrypt"
       hash = "6561cbfe957c9309d2c368541a83d7c68effb5b9e22263bbafacec31dea927f1"
       date = "2022-12-22"
    strings:
        //InitHook
        $s1 = { 48 8B 05 61 3A 01 00 48 89 44 24 20 4C 8D 0D 5D 3A 01 00 4C 8D 05 6C E2 FF FF 48 8D 15 C7 F2 00 00 48 8D 0D F8 F2 00 00 E8 73 E6 FF FF }
        //RES Decryption
        $s2 = { 48 89 45 08 48 8D 0D 58 ED 00 00 E8 43 DE FF FF 48 8B 4D 08 E8 12 DE FF FF BA 04 00 00 00 48 8B C8 FF 15 74 7F 01 00 }
        //Disable Hook
        $s3 = { 48 89 4C 24 08 57 48 83 EC 20 33 D2 48 8B 4C 24 30 E8 1A 10 00 00 48 83 C4 20 }
        //Relocate DLL
        $s4 = { 48 8B 85 C8 01 00 00 48 8B 40 18 48 8B 8D C0 01 00 00 48 2B C8 48 8B C1 48 89 45 08 48 83 7D 08 00 }
    

    condition:
        // Detect if it a PE File and detects all opcodes 
        uint16(0) == 0x5A4D and all of them

  }
