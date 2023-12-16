package sm3

import (
    "testing"
)

func Test_Rand(t *testing.T) {
    nonce := []byte("nonce-asdfg")
    label := []byte("label-asdfg")
    addin := []byte("addin-ftgyj")

    out := make([]byte, 16)

    r := NewRand(nonce, label)
    r.Generate(addin, out)

    if len(out) == 0 {
        t.Error("Rand make error")
    }

    if len(out) != 16 {
        t.Error("Rand make length error")
    }
}
