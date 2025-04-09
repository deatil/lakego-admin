package whirlx

import (
    "errors"
    "crypto/cipher"

    "github.com/deatil/go-cryptobin/tool/alias"
)

const BlockSize = 16

const Rounds = 16

type whirlxCipher struct {
    key []byte
}

// NewCipher creates and returns a new cipher.Block.
// The whirlx and ginga is a same cipher.
func NewCipher(key []byte) (cipher.Block, error) {
    k := len(key)
    switch k {
        case 16, 32:
            break
        default:
            return nil, errors.New("go-cryptobin/whirlx: invalid key size (must be 16 or 32 bytes)")
    }

    c := new(whirlxCipher)
    c.expandKey(key)

    return c, nil
}

func (c *whirlxCipher) BlockSize() int {
    return BlockSize
}

func (c *whirlxCipher) Encrypt(dst, src []byte) {
    if len(src) < BlockSize {
        panic("go-cryptobin/whirlx: input not full block")
    }
    if len(dst) < BlockSize {
        panic("go-cryptobin/whirlx: output not full block")
    }
    if alias.InexactOverlap(dst[:BlockSize], src[:BlockSize]) {
        panic("go-cryptobin/whirlx: invalid buffer overlap")
    }

    out := c.encrypt(src[:BlockSize])
    copy(dst, out)
}

func (c *whirlxCipher) Decrypt(dst, src []byte) {
    if len(src) < BlockSize {
        panic("go-cryptobin/whirlx: input not full block")
    }
    if len(dst) < BlockSize {
        panic("go-cryptobin/whirlx: output not full block")
    }
    if alias.InexactOverlap(dst[:BlockSize], src[:BlockSize]) {
        panic("go-cryptobin/whirlx: invalid buffer overlap")
    }

    out := c.decrypt(src[:BlockSize])
    copy(dst, out)
}

func (c *whirlxCipher) expandKey(key []byte) {
    c.key = append([]byte{}, key...)
}

func (c *whirlxCipher) encrypt(m []byte) []byte {
    enc := make([]byte, BlockSize)
    copy(enc, m)

    for r := 0; r < Rounds; r++ {
        for i := range enc {
            k := subKey(c.key, r, i)
            enc[i] = round(enc[i], k, r)
        }

        mixState(enc)
    }

    return enc
}

func (c *whirlxCipher) decrypt(m []byte) []byte {
    plain := make([]byte, BlockSize)
    copy(plain, m)

    for r := Rounds - 1; r >= 0; r-- {
        invMixState(plain)

        for i := range plain {
            k := subKey(c.key, r, i)
            plain[i] = invRound(plain[i], k, r)
        }
    }

    return plain
}
