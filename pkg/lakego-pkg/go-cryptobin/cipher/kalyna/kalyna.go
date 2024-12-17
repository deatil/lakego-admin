package kalyna

import (
    "fmt"
    "crypto/cipher"
)

type KeySizeError int

func (k KeySizeError) Error() string {
    return fmt.Sprintf("go-cryptobin/kalyna: invalid key size %d", int(k))
}

// NewCipher creates and returns a new cipher.Block.
func NewCipher(key []byte) (cipher.Block, error) {
    k := len(key)
    switch k {
        case 16:
            return NewCipher128_128(key)
        case 32:
            return NewCipher256_256(key)
        case 64:
            return NewCipher512_512(key)
    }

    return nil, KeySizeError(len(key))
}
