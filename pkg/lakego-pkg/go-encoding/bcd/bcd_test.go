package bcd

import (
    "bytes"
    "testing"
    "encoding/hex"
)

func fromHex(s string) []byte {
    h, _ := hex.DecodeString(s)
    return h
}

func toHex(str string) []byte {
    s := hex.EncodeToString([]byte(str))
    return []byte(s)
}

func fromString(s string) []byte {
    return []byte(s)
}

func Test_nibbleToHexChar(t *testing.T) {
    var tests = []struct {
        bin  byte
        want byte
    }{
        {0x05, '5'},
        {0x0c, 'c'},
    }

    for i, tt := range tests {
        got := nibbleToHexChar(tt.bin)
        if got != tt.want {
            t.Errorf("[%d] bin %d, got %x, want %x", i, tt.bin, got, tt.want)
        }
    }
}

func Test_Encode(t *testing.T) {
    var tests = []struct {
        in   []byte
        want []byte
    }{
        {
            fromString("1231"),
            fromHex("1231"),
        },
        {
            fromString("123ac1"),
            fromHex("123ac1"),
        },
        {
            toHex("ftgyhj"),
            fromHex("66746779686a"),
        },
        {
            toHex("ftgyhj;,klioyuiyt90-[[';lkl"),
            fromHex("66746779686a3b2c6b6c696f797569797439302d5b5b273b6c6b6c"),
        },
    }

    for i, tt := range tests {
        got := Encode(tt.in)
        if !bytes.Equal(got, tt.want) {
            t.Errorf("[%d] Encode, got %x, want %x", i, got, tt.want)
        }
    }

    // ========

    for i, tt := range tests {
        got := Decode(tt.want)
        if !bytes.Equal(got, tt.in) {
            t.Errorf("[%d] Decode, got %s, want %s", i, got, tt.in)
        }
    }
}

func Test_Uint32ToBCD(t *testing.T) {
    var tests = []struct {
        in   uint32
        want uint32
    }{
        {0x05, 5},
        {0x0c, 18},
    }

    for i, tt := range tests {
        got, _ := Uint32ToBCD(tt.in)
        if got != tt.want {
            t.Errorf("[%d] Uint32ToBCD, got %d, want %d", i, got, tt.want)
        }
    }

    // =======

    for i, tt := range tests {
        got, _ := BCDtoUint32(tt.want)
        if got != tt.in {
            t.Errorf("[%d] BCDtoUint32, got %d, want %d", i, got, tt.in)
        }
    }
}
