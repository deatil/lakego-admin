package hash

import (
    "bytes"
    "testing"
)

func Test_Siphash64(t *testing.T) {
    var key [16]byte
    var in []byte
    var i int

    expected := []byte{ 0xdb, 0x9b, 0xc2, 0x57, 0x7f, 0xcc, 0x2a, 0x3f, }

    for i = 0; i < 16; i++ {
        key[i] = byte(i)
    }

    inlen := 16
    in = make([]byte, inlen)
    for i = 0; i < inlen; i++ {
        in[i] = byte(i)
    }

    res := FromBytes(in[:]).Siphash64(key[:]).ToBytes()

    if !bytes.Equal(expected, res) {
        t.Errorf("Check Hash error, got %x, want %x", res, expected)
    }
}

func Test_Siphash128(t *testing.T) {
    var key [16]byte
    var in []byte
    var i int

    expected := []byte{ 0x9e, 0x25, 0xfc, 0x83, 0x3f, 0x22, 0x90, 0x73, 0x3e, 0x93, 0x44, 0xa5, 0xe8, 0x38, 0x39, 0xeb, }

    for i = 0; i < 16; i++ {
        key[i] = byte(i)
    }

    inlen := 20
    in = make([]byte, inlen)
    for i = 0; i < inlen; i++ {
        in[i] = byte(i)
    }

    res := FromBytes(in[:]).Siphash128(key[:]).ToBytes()

    if !bytes.Equal(expected, res) {
        t.Errorf("Check Hash error, got %x, want %x", res, expected)
    }
}
