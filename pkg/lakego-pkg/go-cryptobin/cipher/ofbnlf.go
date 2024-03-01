package cipher

import (
    "crypto/cipher"

    "github.com/deatil/go-cryptobin/tool/alias"
)

type KeyCreator = func([]byte) (cipher.Block, error)

type ofbnlf struct {
    newKey    KeyCreator
    b         cipher.Block
    blockSize int
    iv        []byte
}

func newOFBNLF(b cipher.Block, newKey KeyCreator, iv []byte) *ofbnlf {
    c := &ofbnlf{
        b:         b,
        newKey:    newKey,
        blockSize: b.BlockSize(),
        iv:        make([]byte, b.BlockSize()),
    }

    copy(c.iv, iv)

    return c
}

type ofbnlfEncrypter ofbnlf

func NewOFBNLFEncrypter(newKey KeyCreator, key, iv []byte) cipher.BlockMode {
    b, err := newKey(key)
    if err != nil {
        panic("cryptobin/ofbnlf.NewOFBNLFEncrypter: " + err.Error())
    }

    if len(iv) != b.BlockSize() {
        panic("cryptobin/ofbnlf: IV length must equal block size")
    }

    c := newOFBNLF(b, newKey, iv)

    return (*ofbnlfEncrypter)(c)
}

func (x *ofbnlfEncrypter) BlockSize() int {
    return x.blockSize
}

func (x *ofbnlfEncrypter) CryptBlocks(dst, src []byte) {
    if len(src)%x.blockSize != 0 {
        panic("cryptobin/ofbnlf: input not full blocks")
    }

    if len(dst) < len(src) {
        panic("cryptobin/ofbnlf: output smaller than input")
    }

    if alias.InexactOverlap(dst[:len(src)], src) {
        panic("cryptobin/ofbnlf: invalid buffer overlap")
    }

    iv := x.iv
    k := make([]byte, x.blockSize)

    for len(src) > 0 {
        x.b.Encrypt(k, iv)

        c, err := x.newKey(k)
        if err != nil {
            panic("cryptobin/ofbnlf: " + err.Error())
        }

        c.Encrypt(dst, src)

        src = src[x.blockSize:]
        dst = dst[x.blockSize:]

        copy(iv, k)
    }

    copy(x.iv, iv)
}

func (x *ofbnlfEncrypter) SetIV(iv []byte) {
    if len(iv) != len(x.iv) {
        panic("cryptobin/ofbnlf: incorrect length IV")
    }

    copy(x.iv, iv)
}

type ofbnlfDecrypter ofbnlf

func NewOFBNLFDecrypter(newKey KeyCreator, key, iv []byte) cipher.BlockMode {
    b, err := newKey(key)
    if err != nil {
        panic("cryptobin/ofbnlf.NewOFBNLFDecrypter: " + err.Error())
    }

    if len(iv) != b.BlockSize() {
        panic("cryptobin/ofbnlf: IV length must equal block size")
    }

    c := newOFBNLF(b, newKey, iv)

    return (*ofbnlfDecrypter)(c)
}

func (x *ofbnlfDecrypter) BlockSize() int {
    return x.blockSize
}

func (x *ofbnlfDecrypter) CryptBlocks(dst, src []byte) {
    if len(src)%x.blockSize != 0 {
        panic("cryptobin/ofbnlf: input not full blocks")
    }

    if len(dst) < len(src) {
        panic("cryptobin/ofbnlf: output smaller than input")
    }

    if alias.InexactOverlap(dst[:len(src)], src) {
        panic("cryptobin/ofbnlf: invalid buffer overlap")
    }

    if len(src) == 0 {
        return
    }

    iv := x.iv
    k := make([]byte, x.blockSize)

    for len(src) > 0 {
        x.b.Encrypt(k, iv)

        c, err := x.newKey(k)
        if err != nil {
            panic("cryptobin/ofbnlf: " + err.Error())
        }

        c.Decrypt(dst, src)

        src = src[x.blockSize:]
        dst = dst[x.blockSize:]

        copy(iv, k)
    }

    copy(x.iv, iv)
}

func (x *ofbnlfDecrypter) SetIV(iv []byte) {
    if len(iv) != len(x.iv) {
        panic("cryptobin/ofbnlf: incorrect length IV")
    }

    copy(x.iv, iv)
}
