package aria

import (
    "fmt"
    "crypto/cipher"

    "github.com/deatil/go-cryptobin/tool/alias"
)

const BlockSize = 16

// KeySizeError is returned when key size in bytes
// isn't one of 16, 24, or 32.
type KeySizeError int

func (k KeySizeError) Error() string {
    return fmt.Sprintf("cryptobin/aria: invalid key size %d", int(k))
}

type ariaCipher struct {
    k   int // Key size in bytes.
    enc []uint32
    dec []uint32
}

// NewCipher creates and returns a new cipher.Block.
// The key argument should be the ARIA key,
// either 16, 24, or 32 bytes to select
// ARIA-128, ARIA-192, or AES-256.
func NewCipher(key []byte) (cipher.Block, error) {
    k := len(key)
    switch k {
        case 16, 24, 32:
            break
        default:
            return nil, KeySizeError(k)
    }

    n := k + 36
    c := ariaCipher{
        k:   k,
        enc: make([]uint32, n),
        dec: make([]uint32, n),
    }

    c.expandKey(key)

    return &c, nil
}

func (c *ariaCipher) BlockSize() int {
    return BlockSize
}

func (c *ariaCipher) Encrypt(dst, src []byte) {
    if len(src) < BlockSize {
        panic("cryptobin/aria: input not full block")
    }

    if len(dst) < BlockSize {
        panic("cryptobin/aria: output not full block")
    }

    if alias.InexactOverlap(dst[:BlockSize], src[:BlockSize]) {
        panic("cryptobin/aria: invalid buffer overlap")
    }

    c.cryptBlock(c.enc, dst, src)
}

func (c *ariaCipher) Decrypt(dst, src []byte) {
    if len(src) < BlockSize {
        panic("cryptobin/aria: input not full block")
    }

    if len(dst) < BlockSize {
        panic("cryptobin/aria: output not full block")
    }

    if alias.InexactOverlap(dst[:BlockSize], src[:BlockSize]) {
        panic("cryptobin/aria: invalid buffer overlap")
    }

    c.cryptBlock(c.dec, dst, src)
}

func (c *ariaCipher) rounds() int {
    return c.k/4 + 8
}
