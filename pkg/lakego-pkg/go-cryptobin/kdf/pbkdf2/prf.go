package pbkdf2

import (
    "hash"
    "crypto/hmac"
    "crypto/cipher"

    "github.com/deatil/go-cryptobin/hash/cmac"
)

type PRF interface {
    Hash(key []byte) hash.Hash
}

type HmacPRF struct {
    Hasher func() hash.Hash
}

func (prf HmacPRF) Hash(key []byte) hash.Hash {
    return hmac.New(prf.Hasher, key)
}

type CmacPRF struct {
    Cipher func(key []byte) (cipher.Block, error)
}

func (prf CmacPRF) Hash(key []byte) hash.Hash {
    cip, err := prf.Cipher(key)
    if err != nil {
        panic(err.Error())
    }

    hasher, err := cmac.New(cip)
    if err != nil {
        panic(err.Error())
    }

    return hasher
}

