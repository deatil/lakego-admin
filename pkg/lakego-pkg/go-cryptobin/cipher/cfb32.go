package cipher

import (
    "crypto/cipher"
    "encoding/binary"

    "github.com/deatil/go-cryptobin/tool/alias"
)

type cfb32 struct {
    Cipher     cipher.Block
    Nonce      []byte
    blockSize  int
    blockIndex int
    keyStream  []byte
}

func (c *cfb32) XORKeyStream(dst, src []byte) {
    if len(dst) < len(src) {
        panic("cipher/cfb32: output smaller than input")
    }

    if alias.InexactOverlap(dst[:len(src)], src) {
        panic("cipher/cfb32: invalid buffer overlap")
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

        for j := i; j < end; j += 4 {
            iv := binary.BigEndian.Uint32(c.keyStream[c.blockIndex : c.blockIndex+4])
            dt := binary.BigEndian.Uint32(src[j : j+4])
            binary.BigEndian.PutUint32(dst[j:j+4], dt^iv)
            c.Nonce[c.blockIndex], c.Nonce[c.blockIndex+1], c.Nonce[c.blockIndex+2], c.Nonce[c.blockIndex+3] = dst[j], dst[j+1], dst[j+2], dst[j+3]
            c.blockIndex += 4
        }
    }
}

func NewCFB32(c cipher.Block, iv []byte) cipher.Stream {
    if len(iv) != c.BlockSize() {
        panic("cipher/cfb32: iv length must equal block size")
    }

    return &cfb32{
        Cipher:     c,
        Nonce:      iv[:c.BlockSize()],
        blockSize:  c.BlockSize(),
        blockIndex: c.BlockSize(),
        keyStream:  make([]byte, c.BlockSize()),
    }
}

func NewCFB32Encrypter(block cipher.Block, iv []byte) cipher.Stream {
    return NewCFB32(block, iv)
}

func NewCFB32Decrypter(block cipher.Block, iv []byte) cipher.Stream {
    return NewCFB32(block, iv)
}
