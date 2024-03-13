// Package aes implements the CMAC MAC with the AES.
// AES-CMAC is specified in RFC 4493 and RFC 4494.
package aes

import (
    "hash"
    "crypto/aes"

    "github.com/deatil/go-cryptobin/hash/cmac"
)

// Sum computes the AES-CMAC checksum with the given tagsize of msg using the cipher.Block.
func Sum(msg, key []byte, tagsize int) ([]byte, error) {
    c, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }
    return cmac.Sum(msg, c, tagsize)
}

// Verify computes the AES-CMAC checksum with the given tagsize of msg and compares
// it with the given mac. This functions returns true if and only if the given mac
// is equal to the computed one.
func Verify(mac, msg, key []byte, tagsize int) bool {
    c, err := aes.NewCipher(key)
    if err != nil {
        return false
    }

    return cmac.Verify(mac, msg, c, tagsize)
}

// New returns a hash.Hash computing the AES-CMAC checksum.
func New(key []byte) (hash.Hash, error) {
    return NewWithTagSize(key, aes.BlockSize)
}

// NewWithTagSize returns a hash.Hash computing the AES-CMAC checksum with the
// given tag size. The tag size must between the 1 and the cipher's block size.
func NewWithTagSize(key []byte, tagsize int) (hash.Hash, error) {
    c, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }

    return cmac.NewWithTagSize(c, tagsize)
}
