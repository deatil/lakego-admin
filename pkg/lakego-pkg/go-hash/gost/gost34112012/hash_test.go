package gost34112012

import (
    "fmt"
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

func Test_Check(t *testing.T) {
    in := []byte("nonce-asdfg")
    check := "56d6dd148d3df5947b54f0a0fb5e5b0234680cd7b4614bf3005c86fffb45257419b3133c39e551347cd3ad26850bd9513877ee2b708829f3f8f902377720655f"

    h := New(64)
    h.Write(in)

    out := h.Sum(nil)

    if fmt.Sprintf("%x", out) != check {
        t.Errorf("Check error. got %x, want %s", out, check)
    }
}
