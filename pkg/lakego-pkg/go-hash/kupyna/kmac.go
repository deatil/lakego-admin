package kupyna

import (
    "fmt"
    "hash"
)

type KeySizeError int

func (k KeySizeError) Error() string {
    return fmt.Sprintf("go-hash/kupyna: invalid key size %d", int(k))
}

// NewKmac returns a new hash.Hash computing the Kmac checksum
func NewKmac(key []byte) (hash.Hash, error) {
    l := len(key)
    switch l {
        case 32:
            return NewKmac256(key)
        case 48:
            return NewKmac384(key)
        case 64:
            return NewKmac512(key)
    }

    return nil, KeySizeError(l)
}
