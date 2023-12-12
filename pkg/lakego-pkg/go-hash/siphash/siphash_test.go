package siphash

import (
    "bytes"
    "testing"
)

func Test_Hash(t *testing.T) {
    key := []byte("1234567812345678")
    data := []byte("test data")

    h := New(key)
    h.Write(data)
    res := h.Sum(nil)

    if len(res) == 0 {
        t.Error("Hash error")
    }
}

func Test_Check8(t *testing.T) {
    var key [KEY_SIZE]byte
    var in []byte
    var i int

    expected := []byte{ 0xdb, 0x9b, 0xc2, 0x57, 0x7f, 0xcc, 0x2a, 0x3f, }

    for i = 0; i < KEY_SIZE; i++ {
        key[i] = byte(i)
    }

    inlen := 16
    in = make([]byte, inlen)
    for i = 0; i < inlen; i++ {
        in[i] = byte(i)
    }

    h := NewWithCDroundsAndHashSize(key[:], 0, 0, 8)
    h.Write(in[:])
    res := h.Sum(nil)

    if !bytes.Equal(expected, res) {
        t.Errorf("Check Hash error, got %x, want %x", res, expected)
    }
}

func Test_Check16(t *testing.T) {
    var key [KEY_SIZE]byte
    var in []byte
    var i int

    expected := []byte{ 0x9e, 0x25, 0xfc, 0x83, 0x3f, 0x22, 0x90, 0x73, 0x3e, 0x93, 0x44, 0xa5, 0xe8, 0x38, 0x39, 0xeb, }

    for i = 0; i < KEY_SIZE; i++ {
        key[i] = byte(i)
    }

    inlen := 20
    in = make([]byte, inlen)
    for i = 0; i < inlen; i++ {
        in[i] = byte(i)
    }

    h := NewWithCDroundsAndHashSize(key[:], 0, 0, 16)
    h.Write(in[:])
    res := h.Sum(nil)

    if !bytes.Equal(expected, res) {
        t.Errorf("Check Hash error, got %x, want %x", res, expected)
    }
}
