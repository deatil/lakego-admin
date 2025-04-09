package siv

import (
    "crypto/cipher"
)

// Minimum nonce size for which we'll allow the generation of random nonces
const minimumRandomNonceSize = 16

// aead is a wrapper for Cipher implementing cipher.AEAD interface.
type aead struct {
    // Cipher instance underlying this AEAD
    c *Cipher

    // Size of the nonce required
    nonceSize int
}

// NewCMAC returns an SIV instance implementing cipher.AEAD interface
//
// Unless the given nonce size is less than zero, Seal and Open will panic when
// passed nonce of a different size.
func NewCMAC(macBlock, ctrBlock cipher.Block, nonceSize int) (cipher.AEAD, error) {
    c, err := NewCMACCipher(macBlock, ctrBlock)
    if err != nil {
        return nil, err
    }

    return &aead{
        c:         c,
        nonceSize: nonceSize,
    }, nil
}

// NewPMAC returns an SIV instance implementing cipher.AEAD interface
//
// Unless the given nonce size is less than zero, Seal and Open will panic when
// passed nonce of a different size.
func NewPMAC(macBlock, ctrBlock cipher.Block, nonceSize int) (cipher.AEAD, error) {
    c, err := NewPMACCipher(macBlock, ctrBlock)
    if err != nil {
        return nil, err
    }

    return &aead{
        c:         c,
        nonceSize: nonceSize,
    }, nil
}

// NewSiv returns an SIV instance implementing cipher.AEAD interface
func NewSiv(macBlock, ctrBlock cipher.Block, nonceSize int) (cipher.AEAD, error) {
    return NewCMAC(macBlock, ctrBlock, nonceSize)
}

func (a *aead) NonceSize() int {
    return a.nonceSize
}

func (a *aead) Overhead() int  {
    return a.c.Overhead()
}

func (a *aead) Seal(dst, nonce, plaintext, data []byte) (out []byte) {
    if len(nonce) != a.nonceSize && a.nonceSize >= 0 {
        panic("go-cryptobin/siv: incorrect nonce length")
    }

    var err error
    if data == nil {
        out, err = a.c.Seal(dst, plaintext, nonce)
    } else {
        out, err = a.c.Seal(dst, plaintext, data, nonce)
    }

    if err != nil {
        panic("go-cryptobin/siv: " + err.Error())
    }

    return out
}

func (a *aead) Open(dst, nonce, ciphertext, data []byte) ([]byte, error) {
    if len(nonce) != a.nonceSize && a.nonceSize >= 0 {
        panic("go-cryptobin/siv: incorrect nonce length")
    }

    if data == nil {
        return a.c.Open(dst, ciphertext, nonce)
    }

    return a.c.Open(dst, ciphertext, data, nonce)
}
