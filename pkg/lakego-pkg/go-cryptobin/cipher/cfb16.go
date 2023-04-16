package cipher

import (
    "crypto/cipher"

    "github.com/deatil/go-cryptobin/tool/alias"
)

// cfb16 is a custom CFB-16 cipher mode for Cipher.
type cfb16 struct {
    Cipher     cipher.Block
    Nonce      []byte
    blockSize  int
    blockIndex int
    keyStream  []byte
}

func (c *cfb16) XORKeyStream(dst, src []byte) {
    if len(dst) < len(src) {
        panic("output smaller than input")
    }

    if alias.InexactOverlap(dst[:len(src)], src) {
        panic("invalid buffer overlap")
    }

    if c.blockIndex == c.blockSize {
        // Encrypt the nonce to generate the initial key stream.
        c.Cipher.Encrypt(c.keyStream, c.Nonce)
        c.blockIndex = 0
    }

    for i := 0; i < len(src); i += c.blockSize {
        if c.blockIndex == c.blockSize {
            // Encrypt the previous ciphertext block to generate the key stream.
            c.Cipher.Encrypt(c.keyStream, c.keyStream)
            c.blockIndex = 0
        }

        // XOR the plaintext with the key stream.
        end := i + c.blockSize
        if end > len(src) {
            end = len(src)
        }

        for j := i; j < end; j++ {
            dst[j] = src[j] ^ c.keyStream[c.blockIndex]
            c.Nonce[c.blockIndex] = dst[j]
            c.blockIndex++
        }
    }
}

func NewCFB16(c cipher.Block, iv []byte) cipher.Stream {
    if len(iv) != c.BlockSize() {
        panic("iv length must equal block size")
    }

    return &cfb16{
        Cipher:     c,
        Nonce:      iv[:c.BlockSize()],
        blockSize:  c.BlockSize(),
        blockIndex: c.BlockSize(),
        keyStream:  make([]byte, c.BlockSize()),
    }
}

func NewCFB16Encrypter(block cipher.Block, iv []byte) cipher.Stream {
    return NewCFB16(block, iv)
}

func NewCFB16Decrypter(block cipher.Block, iv []byte) cipher.Stream {
    return NewCFB16(block, iv)
}
