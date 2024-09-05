package cipher

import (
    "crypto/cipher"

    "github.com/deatil/go-cryptobin/tool/alias"
)

// CFB stream with 8 bit segment size
// See http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf
type cfb8 struct {
    b         cipher.Block
    blockSize int
    in        []byte
    out       []byte

    decrypt bool
}

func (x *cfb8) XORKeyStream(dst, src []byte) {
    if len(dst) < len(src) {
        panic("cryptobin/cfb8: output smaller than input")
    }
    if alias.InexactOverlap(dst[:len(src)], src) {
        panic("cryptobin/cfb8: invalid buffer overlap")
    }

    for i := range src {
        x.b.Encrypt(x.out, x.in)

        copy(x.in[:x.blockSize-1], x.in[1:])
        if x.decrypt {
            x.in[x.blockSize-1] = src[i]
        }

        dst[i] = src[i] ^ x.out[0]
        if !x.decrypt {
            x.in[x.blockSize-1] = dst[i]
        }
    }
}

func NewCFB8(block cipher.Block, iv []byte, decrypt bool) cipher.Stream {
    blockSize := block.BlockSize()
    if len(iv) != blockSize {
        // stack trace will indicate whether it was de or encryption
        panic("cryptobin/cfb8: IV length must equal block size")
    }

    x := &cfb8{
        b:         block,
        blockSize: blockSize,
        out:       make([]byte, blockSize),
        in:        make([]byte, blockSize),
        decrypt:   decrypt,
    }
    copy(x.in, iv)

    return x
}

// NewCFB8Encrypter returns a Stream which encrypts with cipher feedback mode
// (segment size = 8), using the given Block. The iv must be the same length as
// the Block's block size.
func NewCFB8Encrypter(block cipher.Block, iv []byte) cipher.Stream {
    return NewCFB8(block, iv, false)
}

// NewCFB8Decrypter returns a Stream which decrypts with cipher feedback mode
// (segment size = 8), using the given Block. The iv must be the same length as
// the Block's block size.
func NewCFB8Decrypter(block cipher.Block, iv []byte) cipher.Stream {
    return NewCFB8(block, iv, true)
}
