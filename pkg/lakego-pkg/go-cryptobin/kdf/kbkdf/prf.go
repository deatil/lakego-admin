package kbkdf

import (
    "hash"
    "crypto/hmac"
    "crypto/cipher"

    "github.com/deatil/go-cryptobin/hash/cmac"
)

type hmacPRF struct {
    hash func() hash.Hash
}

// New HMAC-based Pseudo-Random Functions
func NewHMACPRF(h func() hash.Hash) PRF {
    return &hmacPRF{
        hash: h,
    }
}

func (prf *hmacPRF) Sum(key []byte, src ...[]byte) []byte {
    h := hmac.New(prf.hash, key)

    for _, v := range src {
        h.Write(v)
    }

    return h.Sum(nil)
}

// ================

type cmacPRF struct {
    cipher func(key []byte) (cipher.Block, error)
}

// New CMAC-based Pseudo-Random Functions
func NewCMACPRF(cip func(key []byte) (cipher.Block, error)) PRF {
    return &cmacPRF{
        cipher: cip,
    }
}

func (prf *cmacPRF) Sum(key []byte, src ...[]byte) []byte {
    b, err := prf.cipher(key)
    if err != nil {
        panic(err)
    }

    h, err := cmac.New(b)
    if err != nil {
        panic(err)
    }

    for _, v := range src {
        h.Write(v)
    }

    return h.Sum(nil)
}
