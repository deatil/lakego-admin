package gost341194

import (
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
