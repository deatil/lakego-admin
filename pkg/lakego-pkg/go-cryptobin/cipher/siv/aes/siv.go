package aes

import (
    "errors"
    "crypto/aes"
    "crypto/cipher"

    "github.com/deatil/go-cryptobin/cipher/siv"
)

var KeySizeErr = errors.New("siv: bad key size")

// NewCMAC returns an SIV instance implementing cipher.AEAD interface
//
// Unless the given nonce size is less than zero, Seal and Open will panic when
// passed nonce of a different size.
func NewCMAC(key []byte, nonceSize int) (cipher.AEAD, error) {
    n := len(key)
    if n != 32 && n != 64 {
        return nil, KeySizeErr
    }

    macBlock, err := aes.NewCipher(key[:n/2])
    if err != nil {
        return nil, err
    }

    ctrBlock, err := aes.NewCipher(key[n/2:])
    if err != nil {
        return nil, err
    }

    return siv.NewCMAC(macBlock, ctrBlock, nonceSize)
}

// NewPMAC returns an SIV instance implementing cipher.AEAD interface
//
// Unless the given nonce size is less than zero, Seal and Open will panic when
// passed nonce of a different size.
func NewPMAC(key []byte, nonceSize int) (cipher.AEAD, error) {
    n := len(key)
    if n != 32 && n != 64 {
        return nil, KeySizeErr
    }

    macBlock, err := aes.NewCipher(key[:n/2])
    if err != nil {
        return nil, err
    }

    ctrBlock, err := aes.NewCipher(key[n/2:])
    if err != nil {
        return nil, err
    }

    return siv.NewPMAC(macBlock, ctrBlock, nonceSize)
}

// NewSiv returns an SIV instance implementing cipher.AEAD interface
func NewSiv(key []byte, nonceSize int) (cipher.AEAD, error) {
    return NewCMAC(key, nonceSize)
}
