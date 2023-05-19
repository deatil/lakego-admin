package aria

import (
    "fmt"
    "crypto/cipher"
)

// code from github.com/hallazzang/aria-go

// BlockSize is the ARIA block size in bytes.
const BlockSize = 16

type ariaCipher struct {
    k   int // Key size in bytes.
    enc []uint32
    dec []uint32
}

// KeySizeError is returned when key size in bytes
// isn't one of 16, 24, or 32.
type KeySizeError int

func (k KeySizeError) Error() string {
    return fmt.Sprintf("cipher/aria: invalid key size %d", int(k))
}

// NewCipher creates and returns a new cipher.Block.
// The key argument should be the ARIA key,
// either 16, 24, or 32 bytes to select
// ARIA-128, ARIA-192, or AES-256.
func NewCipher(key []byte) (cipher.Block, error) {
    k := len(key)
    switch k {
        default:
            return nil, KeySizeError(k)
        case 128 / 8, 192 / 8, 256 / 8:
            break
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

func (c *ariaCipher) BlockSize() int { return BlockSize }

func (c *ariaCipher) Encrypt(dst, src []byte) {
    if len(src) < BlockSize {
        panic("aria: input not full block")
    }
    
    if len(dst) < BlockSize {
        panic("aria: output not full block")
    }
    
    if inexactOverlap(dst[:BlockSize], src[:BlockSize]) {
        panic("aria: invalid buffer overlap")
    }
    
    c.cryptBlock(c.enc, dst, src)
}

func (c *ariaCipher) Decrypt(dst, src []byte) {
    if len(src) < BlockSize {
        panic("aria: input not full block")
    }
    
    if len(dst) < BlockSize {
        panic("aria: output not full block")
    }
    
    if inexactOverlap(dst[:BlockSize], src[:BlockSize]) {
        panic("aria: invalid buffer overlap")
    }
    
    c.cryptBlock(c.dec, dst, src)
}

func (c *ariaCipher) rounds() int {
    return c.k/4 + 8
}
