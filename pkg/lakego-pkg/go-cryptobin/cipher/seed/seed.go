package seed

import (
    "errors"
    "strconv"
    "crypto/cipher"
)

// code from github.com/geeksbaek/seed

// BlockSize is The SEED128 block size in bytes.
const BlockSize = 16

const (
    // noRounds     = 16
    // noRoundKeys  = 32
    // seedBlockLen = 128
)

type seed128Cipher struct {
    pdwRoundKey []uint32
}

// KeySizeError is Invalid Key Size Error.
type KeySizeError int

func (k KeySizeError) Error() string {
    return "cipher/seed: Invalid key size " + strconv.Itoa(int(k))
}

// NewCipher creates and returns a new cipher.Block.
// The key argument should be 16 bytes.
func NewCipher(key []byte) (cipher.Block, error) {
    k := len(key)
    switch k {
        case 16:
            break
        case 32:
            return nil, errors.New("cipher/seed: Unsupported key size 32")
        default:
            return nil, KeySizeError(k)
    }
    
    return newCipherGeneric(key)
}

func newCipherGeneric(key []byte) (cipher.Block, error) {
    n := len(key) + 28
    c := seed128Cipher{make([]uint32, n)}
    c.pdwRoundKey = seedRoundKey(key)
    return &c, nil
}

func (c *seed128Cipher) BlockSize() int { return BlockSize }

func (c *seed128Cipher) Encrypt(dst, src []byte) {
    if len(src) < BlockSize {
        panic("cipher/seed: input not full block")
    }
    
    if len(dst) < BlockSize {
        panic("cipher/seed: output not full block")
    }
    
    // if subtle.InexactOverlap(dst[:BlockSize], src[:BlockSize]) {
    //   panic("cipher/seed: invalid buffer overlap")
    // }
    
    seedEncrypt(c.pdwRoundKey, dst, src)
}

func (c *seed128Cipher) Decrypt(dst, src []byte) {
    if len(src) < BlockSize {
        panic("cipher/seed: input not full block")
    }
    
    if len(dst) < BlockSize {
        panic("cipher/seed: output not full block")
    }
    
    // if subtle.InexactOverlap(dst[:BlockSize], src[:BlockSize]) {
    //   panic("cipher/seed: invalid buffer overlap")
    // }
    
    seedDecrypt(c.pdwRoundKey, dst, src)
}
