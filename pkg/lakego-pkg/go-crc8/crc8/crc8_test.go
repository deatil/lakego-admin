package crc8

import (
    "testing"
)

func Test_Checksum(t *testing.T) {
    var tests = []struct{
        index   string
        params  Params
        data    string
        check   string
        bcheck  string
    }{
        {
            index:   "CRC8",
            params:  CRC8,
            data:    "hjfiusdf123",
            check:   "F0",
            bcheck:  "11110000",
        },
        {
            index:   "CRC8_CDMA2000",
            params:  CRC8_CDMA2000,
            data:    "hjfiusdf123",
            check:   "E2",
            bcheck:  "11100010",
        },
        {
            index:   "CRC8_ITU",
            params:  CRC8_ITU,
            data:    "hjfiusdf123",
            check:   "A5",
            bcheck:  "10100101",
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

        got11 := ToBinString(sum)
        if got11 != td.bcheck {
            t.Errorf("ToBinString error, got %s, want %s, index %s", got11, td.bcheck, td.index)
        }
    }
}
