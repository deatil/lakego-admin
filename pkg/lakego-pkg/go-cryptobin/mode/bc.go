package mode

import (
    "crypto/cipher"
    "crypto/subtle"

    "github.com/deatil/go-cryptobin/tool/alias"
)

type bc struct {
    b         cipher.Block
    blockSize int
    iv        []byte
}

func newBC(b cipher.Block, iv []byte) *bc {
    c := &bc{
        b:         b,
        blockSize: b.BlockSize(),
        iv:        make([]byte, b.BlockSize()),
    }

    copy(c.iv, iv)

    return c
}

type bcEncrypter bc

type bcEncAble interface {
    NewBCEncrypter(iv []byte) cipher.BlockMode
}

func NewBCEncrypter(b cipher.Block, iv []byte) cipher.BlockMode {
    if len(iv) != b.BlockSize() {
        panic("go-cryptobin/bc: IV length must equal block size")
    }

    if bc, ok := b.(bcEncAble); ok {
        return bc.NewBCEncrypter(iv)
    }

    return (*bcEncrypter)(newBC(b, iv))
}

func (x *bcEncrypter) BlockSize() int {
    return x.blockSize
}

func (x *bcEncrypter) CryptBlocks(dst, src []byte) {
    if len(src)%x.blockSize != 0 {
        panic("cryptobin/bc: input not full blocks")
    }

    if len(dst) < len(src) {
        panic("cryptobin/bc: output smaller than input")
    }

    if alias.InexactOverlap(dst[:len(src)], src) {
        panic("cryptobin/bc: invalid buffer overlap")
    }

    iv := x.iv

    for len(src) > 0 {
        subtle.XORBytes(dst[:x.blockSize], src[:x.blockSize], iv)
        x.b.Encrypt(dst[:x.blockSize], dst[:x.blockSize])
        subtle.XORBytes(iv, iv, dst[:x.blockSize])

        src = src[x.blockSize:]
        dst = dst[x.blockSize:]
    }

    copy(x.iv, iv)
}

func (x *bcEncrypter) SetIV(iv []byte) {
    if len(iv) != len(x.iv) {
        panic("cryptobin/bc: incorrect length IV")
    }

    copy(x.iv, iv)
}

type bcDecrypter bc

type bcDecAble interface {
    NewBCDecrypter(iv []byte) cipher.BlockMode
}

func NewBCDecrypter(b cipher.Block, iv []byte) cipher.BlockMode {
    if len(iv) != b.BlockSize() {
        panic("cryptobin/bc: IV length must equal block size")
    }

    if bc, ok := b.(bcDecAble); ok {
        return bc.NewBCDecrypter(iv)
    }

    return (*bcDecrypter)(newBC(b, iv))
}

func (x *bcDecrypter) BlockSize() int {
    return x.blockSize
}

func (x *bcDecrypter) CryptBlocks(dst, src []byte) {
    if len(src)%x.blockSize != 0 {
        panic("cryptobin/bc: input not full blocks")
    }

    if len(dst) < len(src) {
        panic("cryptobin/bc: output smaller than input")
    }

    if alias.InexactOverlap(dst[:len(src)], src) {
        panic("cryptobin/bc: invalid buffer overlap")
    }

    if len(src) == 0 {
        return
    }

    iv := x.iv
    nextIV := make([]byte, x.blockSize)

    for len(src) > 0 {
        subtle.XORBytes(nextIV, iv, src[:x.blockSize])
        x.b.Decrypt(dst[:x.blockSize], src[:x.blockSize])
        subtle.XORBytes(dst[:x.blockSize], dst[:x.blockSize], iv)

        copy(iv, nextIV)
        src = src[x.blockSize:]
        dst = dst[x.blockSize:]
    }

    copy(x.iv, iv)
}

func (x *bcDecrypter) SetIV(iv []byte) {
    if len(iv) != len(x.iv) {
        panic("cryptobin/bc: incorrect length IV")
    }

    copy(x.iv, iv)
}
