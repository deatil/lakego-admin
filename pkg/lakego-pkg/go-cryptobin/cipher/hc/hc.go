package hc

import (
    "strconv"
    "crypto/cipher"
)

type KeySizeError int

func (k KeySizeError) Error() string {
    return "go-cryptobin/hc: invalid key size " + strconv.Itoa(int(k))
}

type IVSizeError int

func (k IVSizeError) Error() string {
    return "go-cryptobin/hc: invalid iv size " + strconv.Itoa(int(k))
}

// NewCipher creates and returns a new cipher.Block.
func NewCipher(key, iv []byte) (cipher.Stream, error) {
    k := len(key)
    switch k {
        case 16:
            return NewCipher128(key, iv)
        case 32:
            return NewCipher256(key, iv)
    }

    return nil, KeySizeError(k)
}
