package cipher

import (
    "crypto/cipher"
)

type cfb1 struct {
    block cipher.Block
    iv    []byte
}

func (c *cfb1) XORKeyStream(dst, src []byte) {
    if len(dst) < len(src) {
        panic("cipher/cfb1: output smaller than input")
    }

    for i := 0; i < len(src); i++ {
        c.block.Encrypt(c.iv, c.iv)
        dst[i] = src[i] ^ c.iv[0]
    }
}

func NewCFB1(block cipher.Block, iv []byte) cipher.Stream {
    if len(iv) != block.BlockSize() {
        panic("cipher/cfb1: iv length must equal block size")
    }

    stream := &cfb1{
        block: block,
        iv:    iv,
    }

    return stream
}

func NewCFB1Encrypter(block cipher.Block, iv []byte) cipher.Stream {
    return NewCFB1(block, iv)
}

func NewCFB1Decrypter(block cipher.Block, iv []byte) cipher.Stream {
    return NewCFB1(block, iv)
}
