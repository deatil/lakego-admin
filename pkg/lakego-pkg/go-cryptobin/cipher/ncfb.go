package cipher

import (
    "crypto/cipher"
    "crypto/subtle"

    "github.com/deatil/go-cryptobin/tool/alias"
)

/**
 * ncfb 模式
 * n CFB (Cipher Feedback) Mode.
 *
 * @create 2023-11-23
 * @author deatil
 */
type ncfb struct {
    b       cipher.Block
    next    []byte
    out     []byte
    outUsed int

    decrypt bool
}

func (x *ncfb) XORKeyStream(dst, src []byte) {
    if len(dst) < len(src) {
        panic("cryptobin/ncfb: output smaller than input")
    }

    if alias.InexactOverlap(dst[:len(src)], src) {
        panic("cryptobin/ncfb: invalid buffer overlap")
    }

    bs := x.b.BlockSize()
    for i := 0; i < len(src); i += bs {
        if x.outUsed == len(x.out) {
            x.b.Encrypt(x.out, x.next)
            x.outUsed = 0
        }

        end := i + bs
        if end > len(src) {
            end = len(src)
        }

        dstBytes := make([]byte, end-i)
        srcBytes := src[i:end]

        if x.decrypt {
            copy(x.next[x.outUsed:], srcBytes)
        }

        subtle.XORBytes(dstBytes, srcBytes, x.out[x.outUsed:])

        copy(dst[i:end], dstBytes)

        if !x.decrypt {
            copy(x.next[x.outUsed:], dstBytes)
        }

        x.outUsed += bs
    }
}

func NewNCFBEncrypter(block cipher.Block, iv []byte) cipher.Stream {
    return newNCFB(block, iv, false)
}

func NewNCFBDecrypter(block cipher.Block, iv []byte) cipher.Stream {
    return newNCFB(block, iv, true)
}

func newNCFB(block cipher.Block, iv []byte, decrypt bool) cipher.Stream {
    blockSize := block.BlockSize()
    if len(iv) != blockSize {
        panic("cryptobin/ncfb: IV length must equal block size")
    }

    x := &ncfb{
        b:       block,
        out:     make([]byte, blockSize),
        next:    make([]byte, blockSize),
        outUsed: blockSize,
        decrypt: decrypt,
    }
    copy(x.next, iv)

    return x
}
