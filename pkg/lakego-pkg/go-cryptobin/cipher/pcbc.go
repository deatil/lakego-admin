package cipher

import (
    "bytes"
    "crypto/cipher"
    "crypto/subtle"

    "github.com/deatil/go-cryptobin/tool/alias"
)

/**
 * 填充密码块链接模式
 *
 * @create 2023-4-21
 * @author deatil
 */
type pcbc struct {
    b         cipher.Block
    blockSize int
    iv        []byte
}

func newPCBC(b cipher.Block, iv []byte) *pcbc {
    return &pcbc{
        b:         b,
        blockSize: b.BlockSize(),
        iv:        bytes.Clone(iv),
    }
}

type pcbcEncrypter pcbc

type pcbcEncAble interface {
    NewPCBCEncrypter(iv []byte) cipher.BlockMode
}

func NewPCBCEncrypter(b cipher.Block, iv []byte) cipher.BlockMode {
    if len(iv) != b.BlockSize() {
        panic("cipher.NewPCBCEncrypter: IV length must equal block size")
    }

    if pcbc, ok := b.(pcbcEncAble); ok {
        return pcbc.NewPCBCEncrypter(iv)
    }

    return (*pcbcEncrypter)(newPCBC(b, iv))
}

func newPCBCGenericEncrypter(b cipher.Block, iv []byte) cipher.BlockMode {
    if len(iv) != b.BlockSize() {
        panic("cipher.NewPCBCEncrypter: IV length must equal block size")
    }
    return (*pcbcEncrypter)(newPCBC(b, iv))
}

func (x *pcbcEncrypter) BlockSize() int {
    return x.blockSize
}

func (x *pcbcEncrypter) CryptBlocks(dst, src []byte) {
    if len(src)%x.blockSize != 0 {
        panic("crypto/cipher: input not full blocks")
    }

    if len(dst) < len(src) {
        panic("crypto/cipher: output smaller than input")
    }

    if alias.InexactOverlap(dst[:len(src)], src) {
        panic("crypto/cipher: invalid buffer overlap")
    }

    iv := x.iv
    prevSrc := make([]byte, len(src))

    i := 0
    for len(src) > 0 {
        // n = 1
        subtle.XORBytes(dst[:x.blockSize], src[:x.blockSize], iv)

        if i > 0 {
            // n > 1
            subtle.XORBytes(dst[:x.blockSize], dst[:x.blockSize], prevSrc[:x.blockSize])
        }

        x.b.Encrypt(dst[:x.blockSize], dst[:x.blockSize])

        // P(n-1)
        copy(prevSrc, src[:x.blockSize])

        // Cn
        iv = dst[:x.blockSize]

        // Pn
        src = src[x.blockSize:]

        // P1 + P2 + ... + Pn
        dst = dst[x.blockSize:]

        i++
    }

    copy(x.iv, iv)
}

func (x *pcbcEncrypter) SetIV(iv []byte) {
    if len(iv) != len(x.iv) {
        panic("cipher: incorrect length IV")
    }

    copy(x.iv, iv)
}

type pcbcDecrypter pcbc

type pcbcDecAble interface {
    NewPCBCDecrypter(iv []byte) cipher.BlockMode
}

func NewPCBCDecrypter(b cipher.Block, iv []byte) cipher.BlockMode {
    if len(iv) != b.BlockSize() {
        panic("cipher.NewPCBCDecrypter: IV length must equal block size")
    }

    if pcbc, ok := b.(pcbcDecAble); ok {
        return pcbc.NewPCBCDecrypter(iv)
    }

    return (*pcbcDecrypter)(newPCBC(b, iv))
}

func newPCBCGenericDecrypter(b cipher.Block, iv []byte) cipher.BlockMode {
    if len(iv) != b.BlockSize() {
        panic("cipher.NewPCBCDecrypter: IV length must equal block size")
    }

    return (*pcbcDecrypter)(newPCBC(b, iv))
}

func (x *pcbcDecrypter) BlockSize() int {
    return x.blockSize
}

func (x *pcbcDecrypter) CryptBlocks(dst, src []byte) {
    if len(src)%x.blockSize != 0 {
        panic("crypto/cipher: input not full blocks")
    }
    if len(dst) < len(src) {
        panic("crypto/cipher: output smaller than input")
    }
    if alias.InexactOverlap(dst[:len(src)], src) {
        panic("crypto/cipher: invalid buffer overlap")
    }
    if len(src) == 0 {
        return
    }

    iv := x.iv

    tmpIv := make([]byte, x.blockSize)
    prevDst := make([]byte, len(dst))

    i := 0

    for len(src) > 0 {
        tmpIv = src[:x.blockSize]

        x.b.Decrypt(dst[:x.blockSize], src[:x.blockSize])

        subtle.XORBytes(dst[:x.blockSize], dst[:x.blockSize], iv)

        if i > 0 {
            subtle.XORBytes(dst[:x.blockSize], dst[:x.blockSize], prevDst[:x.blockSize])
        }

        // P(n-1)
        copy(prevDst, dst[:x.blockSize])

        // Cn
        copy(iv, tmpIv)

        // Pn
        src = src[x.blockSize:]

        // P1 + P2 + ... + Pn
        dst = dst[x.blockSize:]

        i++
    }

    copy(x.iv, iv)
}

func (x *pcbcDecrypter) SetIV(iv []byte) {
    if len(iv) != len(x.iv) {
        panic("cipher: incorrect length IV")
    }

    copy(x.iv, iv)
}
