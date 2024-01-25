package crc16

import (
    "testing"
)

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
            index:   "CRC16_IBM",
            params:  CRC16_IBM,
            data:    "hjfiusdf123",
            check:   "21F6",
            rcheck:  "F621",
            bcheck:  "0010000111110110",
            brcheck: "1111011000100001",
        },
        {
            index:   "CRC16_MODBUS",
            params:  CRC16_MODBUS,
            data:    "hjfiusdf123",
            check:   "C5F0",
            rcheck:  "F0C5",
            bcheck:  "1100010111110000",
            brcheck: "1111000011000101",
        },
        {
            index:   "CRC16_XMODEM",
            params:  CRC16_XMODEM,
            data:    "hjfiusdf123",
            check:   "EA92",
            rcheck:  "92EA",
            bcheck:  "1110101010010010",
            brcheck: "1001001011101010",
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
