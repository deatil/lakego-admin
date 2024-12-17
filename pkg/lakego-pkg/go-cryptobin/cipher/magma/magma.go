package magma

import (
    "strconv"
    "crypto/cipher"

    "github.com/deatil/go-cryptobin/cipher/gost"
)

// GOST 34.12-2015 64-bit (Магма (Magma)) block cipher.

const (
    KeySize   = 32
    BlockSize = 8
)

type KeySizeError int

func (k KeySizeError) Error() string {
    return "go-cryptobin/magma: invalid key size: " + strconv.Itoa(int(k))
}

type magmaCipher struct {
    cip cipher.Block
    blk [BlockSize]byte
}

func NewCipher(key []byte) (cipher.Block, error) {
    if len(key) != KeySize {
        return nil, KeySizeError(len(key))
    }

    c := new(magmaCipher)

    err := c.expandKey(key)
    if err != nil {
        return nil, err
    }

    return c, nil
}

func (c *magmaCipher) BlockSize() int {
    return BlockSize
}

func (c *magmaCipher) Encrypt(dst, src []byte) {
    c.blk[0] = src[7]
    c.blk[1] = src[6]
    c.blk[2] = src[5]
    c.blk[3] = src[4]
    c.blk[4] = src[3]
    c.blk[5] = src[2]
    c.blk[6] = src[1]
    c.blk[7] = src[0]

    c.cip.Encrypt(c.blk[:], c.blk[:])

    dst[0] = c.blk[7]
    dst[1] = c.blk[6]
    dst[2] = c.blk[5]
    dst[3] = c.blk[4]
    dst[4] = c.blk[3]
    dst[5] = c.blk[2]
    dst[6] = c.blk[1]
    dst[7] = c.blk[0]
}

func (c *magmaCipher) Decrypt(dst, src []byte) {
    c.blk[0] = src[7]
    c.blk[1] = src[6]
    c.blk[2] = src[5]
    c.blk[3] = src[4]
    c.blk[4] = src[3]
    c.blk[5] = src[2]
    c.blk[6] = src[1]
    c.blk[7] = src[0]

    c.cip.Decrypt(c.blk[:], c.blk[:])

    dst[0] = c.blk[7]
    dst[1] = c.blk[6]
    dst[2] = c.blk[5]
    dst[3] = c.blk[4]
    dst[4] = c.blk[3]
    dst[5] = c.blk[2]
    dst[6] = c.blk[1]
    dst[7] = c.blk[0]
}

func (c *magmaCipher) expandKey(key []byte) (err error) {
    keyCompatible := make([]byte, KeySize)
    for i := 0; i < KeySize/4; i++ {
        keyCompatible[i*4+0] = key[i*4+3]
        keyCompatible[i*4+1] = key[i*4+2]
        keyCompatible[i*4+2] = key[i*4+1]
        keyCompatible[i*4+3] = key[i*4+0]
    }

    c.cip, err = gost.NewCipher(keyCompatible, gost.SboxTC26gost28147paramZ)
    if err != nil {
        return
    }

    c.blk = [BlockSize]byte{}

    return nil
}
