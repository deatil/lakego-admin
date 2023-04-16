package cfb256

import (
    "crypto/cipher"
    "crypto/subtle"
)

const (
    BlockSize = 32
)

// CFB-256加密器
type cfb256Encrypter struct {
    block cipher.Block
    iv    []byte
    r     [BlockSize]byte
    x     [BlockSize]byte
    c     int
}

// CFB-256解密器
type cfb256Decrypter struct {
    block cipher.Block
    iv    []byte
    r     [BlockSize]byte
    x     [BlockSize]byte
    c     int
}

func (c *cfb256Encrypter) encryptBlock(dst, src []byte) {
    c.block.Encrypt(c.x[:], c.r[:])
    copy(dst, xorBytes(src, c.x[:]))
    copy(c.r[:], append(c.r[c.block.BlockSize():], dst...))
}

func (c *cfb256Decrypter) decryptBlock(dst, src []byte) {
    c.block.Encrypt(c.x[:], c.r[:])
    copy(dst, xorBytes(src, c.x[:]))
    copy(c.r[:], append(c.r[c.block.BlockSize():], src...))
}

// 加密一个字节
func (c *cfb256Encrypter) XORKeyStream(dst, src []byte) {
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
func (c *cfb256Decrypter) XORKeyStream(dst, src []byte) {
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

// 创建一个CFB-256加密器
func NewCFB256Encrypter(block cipher.Block, iv []byte) cipher.Stream {
    if len(iv) != block.BlockSize() {
        panic("iv length must equal block size")
    }

    r := [BlockSize]byte{}
    copy(r[:], iv)

    return &cfb256Encrypter{
        block: block,
        iv:    append([]byte{}, iv...),
        r:     r,
    }
}

// 创建一个CFB-256解密器
func NewCFB256Decrypter(block cipher.Block, iv []byte) cipher.Stream {
    if len(iv) != block.BlockSize() {
        panic("iv length must equal block size")
    }

    r := [BlockSize]byte{}
    copy(r[:], iv)

    return &cfb256Decrypter{
        block: block,
        iv:    append([]byte{}, iv...),
        r:     r,
    }
}
