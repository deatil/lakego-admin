package siphash

import (
    "fmt"
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

func Test_Check64(t *testing.T) {
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

    h := New64(key[:])
    h.Write(in[:])
    res := h.Sum(nil)

    if !bytes.Equal(expected, res) {
        t.Errorf("Check Hash error, got %x, want %x", res, expected)
    }
}

func Test_Check128(t *testing.T) {
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

    h := New128(key[:])
    h.Write(in[:])
    res := h.Sum(nil)

    if !bytes.Equal(expected, res) {
        t.Errorf("Check Hash error, got %x, want %x", res, expected)
    }
}

func Test_Check64_2(t *testing.T) {
    key := []byte("1234567890123456")
    data := []byte("test-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-data")

    expected := "222413ad433d0919"

    h := New64(key)
    h.Write(data)
    res := h.Sum(nil)

    if fmt.Sprintf("%x", res) != expected {
        t.Errorf("Check Hash error, got %x, want %s", res, expected)
    }
}

func Test_Check128_2(t *testing.T) {
    key := []byte("1234567890123456")
    data := []byte("test-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-datatest-data")

    expected := "5cf3da9421aa6e0b24901eca3311900e"

    h := New128(key)
    h.Write(data)
    res := h.Sum(nil)

    if fmt.Sprintf("%x", res) != expected {
        t.Errorf("Check Hash error, got %x, want %s", res, expected)
    }
}
