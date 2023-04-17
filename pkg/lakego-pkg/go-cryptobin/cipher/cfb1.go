package cipher

import (
    "crypto/cipher"
)

type cfb1 struct {
    iv        []byte
    block     cipher.Block
    blockSize int
    out       byte

    decrypt bool
}

func (c *cfb1) XORKeyStream(dst, src []byte) {
    panic("cipher/cfb1: cfb1 no support")
}

func NewCFB1(block cipher.Block, iv []byte, decrypt bool) cipher.Stream {
    if len(iv) != block.BlockSize() {
        panic("cipher/cfb1: IV length must equal block size")
    }

    return &cfb1{
        iv:        iv,
        block:     block,
        blockSize: block.BlockSize(),
        decrypt:   decrypt,
    }
}

func NewCFB1Encrypter(block cipher.Block, iv []byte) cipher.Stream {
    return NewCFB1(block, iv, false)
}

func NewCFB1Decrypter(block cipher.Block, iv []byte) cipher.Stream {
    return NewCFB1(block, iv, true)
}
