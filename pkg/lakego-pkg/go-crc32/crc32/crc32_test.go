package crc32

import (
    "testing"
)

func Test_CRC32_AIXM(t *testing.T) {
    data := "hjfiusdfj8o"

    sum := Checksum([]byte(data), CRC32_AIXM)
    if sum == 0 {
        t.Errorf("Checksum error, got %d", sum)
    }
}

func Test_CRC32_CKSUM(t *testing.T) {
    data := "hjfiusdf123"
    check := "81D5D15B"

    sum := ChecksumCKSUM([]byte(data))
    if sum == 0 {
        t.Errorf("Checksum error, got %d", sum)
    }

    got := ToReverseHexString(sum)
    if got != check {
        t.Errorf("CKSUM error, got %s, want %s", got, check)
    }
}

func Test_Checksum(t *testing.T) {
    var tests = []struct{
        index   string
        params  Params
        data    string
        check   string
        rcheck  string
        bcheck  string
        brcheck string
    }{
        {
            index:   "CRC32_CKSUM",
            params:  CRC32_CKSUM,
            data:    "hjfiusdf123",
            check:   "5BD1D581",
            rcheck:  "81D5D15B",
            bcheck:  "01011011110100011101010110000001",
            brcheck: "10000001110101011101000101011011",
        },
        {
            index:   "CRC32",
            params:  CRC32,
            data:    "hjfiusdf123",
            check:   "919852E7",
            rcheck:  "E7529891",
            bcheck:  "10010001100110000101001011100111",
            brcheck: "11100111010100101001100010010001",
        },
        {
            index:   "CRC32_Castagnoli",
            params:  CRC32_Castagnoli,
            data:    "hjfiusdf123",
            check:   "418F6B0F",
            rcheck:  "0F6B8F41",
            bcheck:  "01000001100011110110101100001111",
            brcheck: "00001111011010111000111101000001",
        },
        {
            index:   "CRC32_Koopman",
            params:  CRC32_Koopman,
            data:    "hjfiusdf123",
            check:   "3914A79D",
            rcheck:  "9DA71439",
            bcheck:  "00111001000101001010011110011101",
            brcheck: "10011101101001110001010000111001",
        },
        {
            index:   "CRC32_CRC32D",
            params:  CRC32_CRC32D,
            data:    "hjfiusdf123",
            check:   "0C92FF27",
            rcheck:  "27FF920C",
            bcheck:  "00001100100100101111111100100111",
            brcheck: "00100111111111111001001000001100",
        },
    }

    for _, td := range tests {
        sum := Checksum([]byte(td.data), td.params)
        if sum == 0 {
            t.Errorf("Checksum error, got %d, index %s", sum, td.index)
        }

        got1 := ToHexString(sum)
        if got1 != td.check {
            t.Errorf("ToHexString error, got %s, want %s, index %s", got1, td.check, td.index)
        }

        got2 := ToReverseHexString(sum)
        if got2 != td.rcheck {
            t.Errorf("ToReverseHexString error, got %s, want %s, index %s", got2, td.rcheck, td.index)
        }

        got11 := ToBinString(sum)
        if got11 != td.bcheck {
            t.Errorf("ToBinString error, got %s, want %s, index %s", got11, td.bcheck, td.index)
        }

        got12 := ToReverseHexBinString(sum)
        if got12 != td.brcheck {
            t.Errorf("ToReverseHexBinString error, got %s, want %s, index %s", got12, td.brcheck, td.index)
        }
    }
}
