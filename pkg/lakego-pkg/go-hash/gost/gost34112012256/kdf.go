package gost34112012256

import (
    "hash"
    "crypto/hmac"
)

func KDF(h func() hash.Hash, key, label, seed []byte) (r []byte) {
    fn := hmac.New(h, key)

    if _, err := fn.Write([]byte{0x01}); err != nil {
        panic(err)
    }
    if _, err := fn.Write(label); err != nil {
        panic(err)
    }

    if _, err := fn.Write([]byte{0x00}); err != nil {
        panic(err)
    }
    if _, err := fn.Write(seed); err != nil {
        panic(err)
    }

    if _, err := fn.Write([]byte{0x01}); err != nil {
        panic(err)
    }
    if _, err := fn.Write([]byte{0x00}); err != nil {
        panic(err)
    }

    r = fn.Sum(nil)

    return r
}
