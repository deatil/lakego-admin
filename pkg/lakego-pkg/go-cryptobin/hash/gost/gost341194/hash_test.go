package gost341194

import (
    "fmt"
    "hash"
    "testing"
    "crypto/cipher"
)

func TestHashInterface(t *testing.T) {
    h := New(NewTestCipher)
    var _ hash.Hash = h
}

func TestVectors(t *testing.T) {
    h := New(NewTestCipher)
    h.Write([]byte("a"))
    hashed := h.Sum(nil)

    if len(hashed) == 0 {
        t.Error("Hash error")
    }
}

func NewTestCipher(key []byte) cipher.Block {
    return &testCipher{}
}

type testCipher struct {}

func (c *testCipher) BlockSize() int {
    return 32
}

func (c *testCipher) Encrypt(dst, src []byte) {
    copy(dst, src)
}

func (c *testCipher) Decrypt(dst, src []byte) {
    copy(dst, src)
}

func Test_Check(t *testing.T) {
    in := []byte("nonce-asdfg")
    check := "08246810594b02216e6f6e633d2d39733c666352565b5b6a344e580c0b4e580c"

    h := New(NewTestCipher)
    h.Write(in)

    out := h.Sum(nil)

    if fmt.Sprintf("%x", out) != check {
        t.Errorf("Check error. got %x, want %s", out, check)
    }
}
