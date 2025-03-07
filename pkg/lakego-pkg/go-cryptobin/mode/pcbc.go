package mode

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
        panic("cryptobin/pcbc.NewPCBCEncrypter: IV length must equal block size")
    }

    if pcbc, ok := b.(pcbcEncAble); ok {
        return pcbc.NewPCBCEncrypter(iv)
    }

    return (*pcbcEncrypter)(newPCBC(b, iv))
}

func newPCBCGenericEncrypter(b cipher.Block, iv []byte) cipher.BlockMode {
    if len(iv) != b.BlockSize() {
        panic("cryptobin/pcbc: IV length must equal block size")
    }
    return (*pcbcEncrypter)(newPCBC(b, iv))
}

func (x *pcbcEncrypter) BlockSize() int {
    return x.blockSize
}

func (x *pcbcEncrypter) CryptBlocks(dst, src []byte) {
    if len(src)%x.blockSize != 0 {
        panic("cryptobin/pcbc: input not full blocks")
    }

    if len(dst) < len(src) {
        panic("cryptobin/pcbc: output smaller than input")
    }

    if alias.InexactOverlap(dst[:len(src)], src) {
        panic("cryptobin/pcbc: invalid buffer overlap")
    }

    iv := x.iv

    bs := x.blockSize
    for i := 0; i < len(src); i += bs {
        subtle.XORBytes(dst[i:i+bs], src[i:i+bs], iv)
        x.b.Encrypt(dst[i:i+bs], dst[i:i+bs])

        subtle.XORBytes(iv, src[i:i+bs], dst[i:i+bs])
    }
}

func (x *pcbcEncrypter) SetIV(iv []byte) {
    if len(iv) != len(x.iv) {
        panic("cryptobin/pcbc: incorrect length IV")
    }

    copy(x.iv, iv)
}

type pcbcDecrypter pcbc

type pcbcDecAble interface {
    NewPCBCDecrypter(iv []byte) cipher.BlockMode
}

func NewPCBCDecrypter(b cipher.Block, iv []byte) cipher.BlockMode {
    if len(iv) != b.BlockSize() {
        panic("cryptobin/pcbc.NewPCBCDecrypter: IV length must equal block size")
    }

    if pcbc, ok := b.(pcbcDecAble); ok {
        return pcbc.NewPCBCDecrypter(iv)
    }

    return (*pcbcDecrypter)(newPCBC(b, iv))
}

func newPCBCGenericDecrypter(b cipher.Block, iv []byte) cipher.BlockMode {
    if len(iv) != b.BlockSize() {
        panic("cryptobin/pcbc: IV length must equal block size")
    }

    return (*pcbcDecrypter)(newPCBC(b, iv))
}

func (x *pcbcDecrypter) BlockSize() int {
    return x.blockSize
}

func (x *pcbcDecrypter) CryptBlocks(dst, src []byte) {
    if len(src)%x.blockSize != 0 {
        panic("cryptobin/pcbc: input not full blocks")
    }

    if len(dst) < len(src) {
        panic("cryptobin/pcbc: output smaller than input")
    }

    if alias.InexactOverlap(dst[:len(src)], src) {
        panic("cryptobin/pcbc: invalid buffer overlap")
    }

    if len(src) == 0 {
        return
    }

    iv := x.iv

    bs := x.blockSize
    for i := 0; i < len(src); i += bs {
        x.b.Decrypt(dst[i:i+bs], src[i:i+bs])
        subtle.XORBytes(dst[i:i+bs], dst[i:i+bs], iv)

        subtle.XORBytes(iv, dst[i:i+bs], src[i:i+bs])
    }
}

func (x *pcbcDecrypter) SetIV(iv []byte) {
    if len(iv) != len(x.iv) {
        panic("cryptobin/pcbc: incorrect length IV")
    }

    copy(x.iv, iv)
}
