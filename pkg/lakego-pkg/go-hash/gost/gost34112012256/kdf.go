package gost34112012256

import (
    "hash"
    "crypto/hmac"
)

type KDF struct {
    h hash.Hash
}

func NewKDF(key []byte) *KDF {
    return &KDF{hmac.New(New, key)}
}

func (kdf *KDF) Derive(dst, label, seed []byte) (r []byte) {
    if _, err := kdf.h.Write([]byte{0x01}); err != nil {
        panic(err)
    }
    if _, err := kdf.h.Write(label); err != nil {
        panic(err)
    }
    if _, err := kdf.h.Write([]byte{0x00}); err != nil {
        panic(err)
    }
    if _, err := kdf.h.Write(seed); err != nil {
        panic(err)
    }
    if _, err := kdf.h.Write([]byte{0x01}); err != nil {
        panic(err)
    }
    if _, err := kdf.h.Write([]byte{0x00}); err != nil {
        panic(err)
    }
    r = kdf.h.Sum(dst)
    kdf.h.Reset()
    return r
}
