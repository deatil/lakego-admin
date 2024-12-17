package seed

import (
    "fmt"
    "crypto/cipher"
)

// Package seed implements SEED encryption, as defined in TTAS.KO-12.0004/R1

const BlockSize = 16

type KeySizeError int

func (k KeySizeError) Error() string {
    return fmt.Sprintf("go-cryptobin/seed: invalid key size %d", int(k))
}

// NewCipher creates and returns a new cipher.Block. The key argument should be the SEED key, either 16 or 32 bytes to select SEED-128 or SEED-256.
func NewCipher(key []byte) (cipher.Block, error) {
    k := len(key)
    switch k {
        case 16:
            return newSeed128Cipher(key), nil
        case 32:
            return newSeed256Cipher(key), nil
    }

    return nil, KeySizeError(k)
}
