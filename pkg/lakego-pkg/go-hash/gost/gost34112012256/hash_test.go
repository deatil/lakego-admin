package gost34112012256

import (
    "hash"
    "testing"
)

func TestHashInterface(t *testing.T) {
    h := New()
    var _ hash.Hash = h
}

func TestHashed(t *testing.T) {
    h := New()
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
