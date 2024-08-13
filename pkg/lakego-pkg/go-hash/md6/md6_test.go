package md6

import (
    "hash"
    "bytes"
    "testing"
    "strings"
    "encoding/hex"
)

func fromHex(s string) []byte {
    h, _ := hex.DecodeString(s)
    return h
}

type testData struct {
    Hash func() hash.Hash
    Msg  string
    Md   []byte
}

func Test_Hash(t *testing.T) {
    tests := []testData{
        {
            Hash: New256,
            Msg:  "md6 FTW",
            Md:   fromHex("7bfaa624f661a683be2a3b2007493006a30a7845ee1670e499927861a8e74cce"),
        },
        {
            Hash: New256,
            Msg:  "The lazy fox jumps over the lazy dog",
            Md:   []byte{
                 0xE4, 0x55, 0x51, 0xAA, 0xE2, 0x66, 0xE1, 0x48,
                 0x2A, 0xC9, 0x8E, 0x24, 0x22, 0x9B, 0x3E, 0x90,
                 0xDC, 0x06, 0x61, 0x77, 0xF8, 0xFB, 0x1A, 0x52,
                 0x6E, 0x9D, 0xA2, 0xCC, 0x95, 0x71, 0x97, 0xAA,
            },
        },
        {
            Hash: New512,
            Msg:  "Zażółć gęślą jaźń",
            Md:   []byte{
                 0x92, 0x4E, 0x91, 0x6A, 0x01, 0x2C, 0x1A, 0x8D,
                 0x0F, 0xB7, 0x9A, 0x4A, 0xD4, 0x9C, 0x55, 0x5E,
                 0xBD, 0xCA, 0x59, 0xB8, 0x1B, 0x4C, 0x13, 0x41,
                 0x2E, 0x32, 0xA5, 0xC9, 0x3B, 0x61, 0xAD, 0xB8,
                 0x4D, 0xB3, 0xF9, 0x0C, 0x03, 0x51, 0xB2, 0x9E,
                 0x7B, 0xAE, 0x46, 0x9F, 0x8D, 0x60, 0x5D, 0xED,
                 0xFF, 0x51, 0x72, 0xDE, 0xA1, 0x6F, 0x00, 0xF7,
                 0xB4, 0x82, 0xEF, 0x87, 0xED, 0x77, 0xD9, 0x1A,
            },
        },
        {
            Hash: New256,
            Msg:  strings.Repeat("123", 3200),
            Md:   fromHex("958ebb6e13cb27151d8a0038c0c42a65a4500e952cf5a5aa44e9a2b63bbc37b9"),
        },
        {
            Hash: New256,
            Msg:  strings.Repeat("tyfrt", 6700),
            Md:   fromHex("c651422a185edab91ff56747a06199023d18fc7ef4251754dcd4aaaebe3bf02c"),
        },
        {
            Hash: New256,
            Msg:  strings.Repeat("tyklret", 15700),
            Md:   fromHex("51fe6756606b05ec27da9d8138c160ebf9a83b80cbdde4c06cf73c4e075ea911"),
        },
    }

    for i, test := range tests {
        h := test.Hash()
        h.Write([]byte(test.Msg))
        sum := h.Sum(nil)

        if !bytes.Equal(sum, test.Md) {
            t.Errorf("[%d] Check error. got %x, want %x", i, sum, test.Md)
        }
    }
}
