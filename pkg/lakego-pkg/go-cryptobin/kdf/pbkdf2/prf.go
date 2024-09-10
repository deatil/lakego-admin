package pbkdf2

import (
    "hash"
    "crypto/hmac"
    "crypto/cipher"

    "github.com/deatil/go-cryptobin/hash/cmac"
)

type PRF interface {
    NewHash(key []byte) hash.Hash
}

type HmacPRF struct {
    Hash func() hash.Hash
}

func NewHmacPRF(h func() hash.Hash) HmacPRF {
    return HmacPRF{
        Hash: h,
    }
}

func (prf HmacPRF) NewHash(key []byte) hash.Hash {
    return hmac.New(prf.Hash, key)
}

type CmacPRF struct {
    Cipher func(key []byte) (cipher.Block, error)
}

func NewCmacPRF(cip func(key []byte) (cipher.Block, error)) CmacPRF {
    return CmacPRF{
        Cipher: cip,
    }
}

func (prf CmacPRF) NewHash(key []byte) hash.Hash {
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

