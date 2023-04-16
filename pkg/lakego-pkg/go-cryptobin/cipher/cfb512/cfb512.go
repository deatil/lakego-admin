package cfb512

import (
    "crypto/cipher"
)

const (
    BlockSize = 64
)

// CFB-512加密器
type cfb512Encrypter struct {
    block cipher.Block
    iv    []byte
    r     [BlockSize]byte
    x     [BlockSize]byte
    c     int
}

// CFB-512解密器
type cfb512Decrypter struct {
    block cipher.Block
    iv    []byte
    r     [BlockSize]byte
    x     [BlockSize]byte
    c     int
}

func (c *cfb512Encrypter) encryptBlock(dst, src []byte) {
    c.block.Encrypt(c.x[:], c.r[:])
    copy(dst, xorBytes(src, c.x[:]))
    copy(c.r[:], append(c.r[c.block.BlockSize():], dst...))
}

func (c *cfb512Decrypter) decryptBlock(dst, src []byte) {
    c.block.Encrypt(c.x[:], c.r[:])
    copy(dst, xorBytes(src, c.x[:]))
    copy(c.r[:], append(c.r[c.block.BlockSize():], src...))
}

// 加密一个字节
func (c *cfb512Encrypter) XORKeyStream(dst, src []byte) {
    if len(src) == 0 {
        return
    }

    for i, s := range src {
        if c.c == 0 {
            c.encryptBlock(c.iv, c.iv)
        }

        dst[i] = s ^ c.iv[c.c]
        c.c = (c.c + 1) % BlockSize
    }
}

// 解密一个字节
func (c *cfb512Decrypter) XORKeyStream(dst, src []byte) {
    if len(src) == 0 {
        return
    }

    for i, s := range src {
        if c.c == 0 {
            c.decryptBlock(c.iv, c.iv)
        }

        dst[i] = s ^ c.iv[c.c]
        c.c = (c.c + 1) % BlockSize
    }
}

func xorBytes(dst, src []byte) []byte {
    n := len(src)
    if len(dst) < n {
        panic("destination must be bigger than source")
    }

    if subtle.InexactOverlap(dst[:n], src) {
        panic("source and destination overlap")
    }

    for i := 0; i < n; i++ {
        dst[i] ^= src[i]
    }

    return dst[:n]
}

// 创建一个CFB-512加密器
func NewCFB512Encrypter(block cipher.Block, iv []byte) cipher.Stream {
    if len(iv) != block.BlockSize() {
        panic("iv length must equal block size")
    }

    r := [BlockSize]byte{}
    copy(r[:], iv)

    return &cfb512Encrypter{
        block: block,
        iv:    append([]byte{}, iv...),
        r:     r,
    }
}

// 创建一个CFB-512解密器
func NewCFB512Decrypter(block cipher.Block, iv []byte) cipher.Stream {
    if len(iv) != block.BlockSize() {
        panic("iv length must equal block size")
    }

    r := [BlockSize]byte{}
    copy(r[:], iv)

    return &cfb512Decrypter{
        block: block,
        iv:    append([]byte{}, iv...),
        r:     r,
    }, nil
}
