package gost34112012

import (
    "hash"
    "encoding"
    "testing"
)

func TestHashInterface(t *testing.T) {
    h := New(64)
    var _ hash.Hash = h
    var _ encoding.BinaryMarshaler = h
    var _ encoding.BinaryUnmarshaler = h
}

func TestHashed(t *testing.T) {
    h := New(64)
    m := make([]byte, BlockSize)
    for i := 0; i < BlockSize; i++ {
        m[i] = byte(i)
    }
    h.Write(m)
    hashed := h.Sum(nil)

    if len(hashed) == 0 {
        t.Error("Hash error")
    }
}
