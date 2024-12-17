package simon

import (
    "fmt"
    "crypto/cipher"
)

const BlockSize = 16

type KeySizeError int

func (k KeySizeError) Error() string {
    return fmt.Sprintf("go-cryptobin/simon: invalid key size %d", int(k))
}

// NewCipher creates and returns a new cipher.Block.
// simon128
func NewCipher(key []byte) (cipher.Block, error) {
    k := len(key)
    switch k {
        case 16:
            return NewCipher128(key)
        case 24:
            return NewCipher192(key)
        case 32:
            return NewCipher256(key)
    }

    return nil, KeySizeError(k)
}
