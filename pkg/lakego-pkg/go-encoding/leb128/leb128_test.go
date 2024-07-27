package leb128

import (
    "bytes"
    "testing"
    "encoding/hex"
)

type PairU struct {
    value   uint64
    encoded string
}

type PairI struct {
    value   int64
    encoded string
}

func fromHex(s string) []byte {
    h, _ := hex.DecodeString(s)
    return h
}

func Test_Basic(t *testing.T) {
    {
        if !bytes.Equal(EncodeUint64(624485), []byte{0xe5, 0x8e, 0x26}) {
            t.Error("EncodeUint64 fail")
        }

        uval, ulen := DecodeUint64([]byte{0xe5, 0x8e, 0x26})
        if uval != 624485 {
            t.Error("DecodeUint64 uval error")
        }
        if ulen != 3 {
            t.Error("DecodeUint64 ulen error")
        }
    }

    {
        if !bytes.Equal(EncodeUint32(624485), []byte{0xe5, 0x8e, 0x26}) {
            t.Error("EncodeUint32 fail")
        }

        uval, ulen := DecodeUint32([]byte{0xe5, 0x8e, 0x26})
        if uval != 624485 {
            t.Error("DecodeUint32 uval error")
        }
        if ulen != 3 {
            t.Error("DecodeUint32 ulen error")
        }
    }

    // =====

    {
        if !bytes.Equal(EncodeInt64(-123456), []byte{0xc0, 0xbb, 0x78}) {
            t.Error("EncodeInt64 fail")
        }

        uval, ulen := DecodeInt64([]byte{0xc0, 0xbb, 0x78})
        if uval != -123456 {
            t.Error("DecodeInt64 uval error")
        }
        if ulen != 3 {
            t.Error("DecodeInt64 ulen error")
        }
    }

    {
        if !bytes.Equal(EncodeInt32(-123456), []byte{0xc0, 0xbb, 0x78}) {
            t.Error("EncodeInt32 fail")
        }

        uval, ulen := DecodeInt32([]byte{0xc0, 0xbb, 0x78})
        if uval != -123456 {
            t.Error("DecodeInt32 uval error")
        }
        if ulen != 3 {
            t.Error("DecodeInt32 ulen error")
        }
    }
}

func Test_Unsigned_Data(t *testing.T) {
    for _, tt := range unsigned_data {
        got := EncodeUint64(tt.value)
        if !bytes.Equal(got, fromHex(tt.encoded)) {
            t.Error("EncodeUint64 fail")
        }

        bytes := fromHex(tt.encoded)
        uval, ulen := DecodeUint64(bytes)
        if uval != tt.value {
            t.Error("DecodeUint64 uval error")
        }
        if ulen != len(bytes) {
            t.Error("DecodeUint64 ulen error")
        }

    }
}

func Test_Signed_Data(t *testing.T) {
    for _, tt := range signed_data {
        got := EncodeInt64(tt.value)
        if !bytes.Equal(got, fromHex(tt.encoded)) {
            t.Error("EncodeInt64 fail")
        }

        bytes := fromHex(tt.encoded)
        uval, ulen := DecodeInt64(bytes)
        if uval != tt.value {
            t.Error("DecodeInt64 uval error")
        }
        if ulen != len(bytes) {
            t.Error("DecodeInt64 ulen error")
        }

    }
}

var unsigned_data = []PairU{
    {217, "d901"},
    {34, "22"},
    {233, "e901"},
    {2049800081, "91efb5d107"},
    {3884507512, "f8c2a3bc0e"},
}

var signed_data = []PairI{
    {71, "c700"},
    {-57, "47"},
    {58, "3a"},
    {1961805726, "9e8fbba707"},
    {-1567520880, "908fc6947a"},
}
