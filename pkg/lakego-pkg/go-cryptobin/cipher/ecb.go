package cipher

import (
    "crypto/cipher"
)

type ecb struct {
    b         cipher.Block
    blockSize int
}

func newECB(b cipher.Block) *ecb {
    return &ecb{
        b:         b,
        blockSize: b.BlockSize(),
    }
}

type ecbEncrypter ecb

// NewECBEncrypter returns a BlockMode which encrypts in electronic code book
// mode, using the given Block.
func NewECBEncrypter(b cipher.Block) cipher.BlockMode {
    return (*ecbEncrypter)(newECB(b))
}

func (this *ecbEncrypter) BlockSize() int { return this.blockSize }
func (this *ecbEncrypter) CryptBlocks(dst, src []byte) {
    if len(src)%this.blockSize != 0 {
        panic("crypto/cipher: input not full blocks")
    }

    if len(dst) < len(src) {
        panic("crypto/cipher: output smaller than input")
    }

    for len(src) > 0 {
        this.b.Encrypt(dst, src[:this.blockSize])
        src = src[this.blockSize:]
        dst = dst[this.blockSize:]
    }
}

type ecbDecrypter ecb

// NewECBDecrypter returns a BlockMode which decrypts in electronic code book
// mode, using the given Block.
func NewECBDecrypter(b cipher.Block) cipher.BlockMode {
    return (*ecbDecrypter)(newECB(b))
}

func (this *ecbDecrypter) BlockSize() int { return this.blockSize }
func (this *ecbDecrypter) CryptBlocks(dst, src []byte) {
    if len(src)%this.blockSize != 0 {
        panic("crypto/cipher: input not full blocks")
    }

    if len(dst) < len(src) {
        panic("crypto/cipher: output smaller than input")
    }

    for len(src) > 0 {
        this.b.Decrypt(dst, src[:this.blockSize])
        src = src[this.blockSize:]
        dst = dst[this.blockSize:]
    }
}
