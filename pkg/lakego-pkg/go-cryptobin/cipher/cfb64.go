package cipher

import (
    "crypto/cipher"
)

type cfb64 struct {
    encrypt   bool
    iv        []byte
    block     cipher.Block
    blockSize int
    out       []byte
}

func (c *cfb64) XORKeyStream(dst, src []byte) {
    for i := range src {
        if len(c.out) == 0 {
            c.block.Encrypt(c.out, c.iv)
        }

        b := src[i]
        if c.encrypt {
            b ^= c.out[0]
        } else {
            c.out[0] ^= src[i]
            b = c.out[0]
        }

        copy(c.out, c.out[1:])
        c.iv[c.blockSize-1] = b
        dst[i] = b
    }
}

func NewCFB64(block cipher.Block, iv []byte, encrypt bool) cipher.Stream {
    if len(iv) != block.BlockSize() {
        panic("cipher/cfb64: iv length must equal block size")
    }

    return &cfb64{
        encrypt:   encrypt,
        iv:        iv,
        block:     block,
        blockSize: block.BlockSize(),
        out:       make([]byte, block.BlockSize()),
    }
}

func NewCFB64Encrypter(block cipher.Block, iv []byte) cipher.Stream {
    return NewCFB64(block, iv, true)
}

func NewCFB64Decrypter(block cipher.Block, iv []byte) cipher.Stream {
    return NewCFB64(block, iv, false)
}
