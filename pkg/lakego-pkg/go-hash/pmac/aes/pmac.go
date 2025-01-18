// Package aes implements the PMAC MAC with the AES.
// AES-PMAC is specified in RFC 4493 and RFC 4494.
package aes

import (
    "hash"
    "crypto/aes"

    "github.com/deatil/go-hash/pmac"
)

// Sum computes the AES-PMAC checksum with the given tagsize of msg using the cipher.Block.
func Sum(msg, key []byte, tagsize int) ([]byte, error) {
    c, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }

    return pmac.Sum(msg, c, tagsize)
}

// Verify computes the AES-PMAC checksum with the given tagsize of msg and compares
// it with the given mac. This functions returns true if and only if the given mac
// is equal to the computed one.
func Verify(mac, msg, key []byte, tagsize int) bool {
    c, err := aes.NewCipher(key)
    if err != nil {
        return false
    }

    return pmac.Verify(mac, msg, c, tagsize)
}

// New returns a hash.Hash computing the AES-PMAC checksum.
func New(key []byte) (hash.Hash, error) {
    return NewWithTagSize(key, aes.BlockSize)
}

// NewWithTagSize returns a hash.Hash computing the AES-PMAC checksum with the
// given tag size. The tag size must between the 1 and the cipher's block size.
func NewWithTagSize(key []byte, tagsize int) (hash.Hash, error) {
    c, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }

    return pmac.NewWithTagSize(c, tagsize)
}
