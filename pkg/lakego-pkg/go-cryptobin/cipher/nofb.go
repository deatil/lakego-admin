package cipher

import (
    "crypto/cipher"
    "crypto/subtle"

    "github.com/deatil/go-cryptobin/tool/alias"
)

/**
 * ncfb 模式
 * NOFB (Output Feedback) Mode.
 *
 * @create 2023-11-23
 * @author deatil
 */
type nofb struct {
    b       cipher.Block
    cipher  []byte
    out     []byte
    outUsed int
}

// NewNOFB returns a Stream that encrypts or decrypts using the block cipher b
// in output feedback mode. The initialization vector iv's length must be equal
// to b's block size.
func NewNOFB(b cipher.Block, iv []byte) cipher.Stream {
    blockSize := b.BlockSize()
    if len(iv) != blockSize {
        panic("cipher/nofb: IV length must equal block size")
    }

    bufSize := streamBufferSize
    if bufSize < blockSize {
        bufSize = blockSize
    }

    x := &nofb{
        b:       b,
        cipher:  make([]byte, blockSize),
        out:     make([]byte, 0, bufSize),
        outUsed: 0,
    }

    copy(x.cipher, iv)
    return x
}

func (x *nofb) refill() {
    bs := x.b.BlockSize()
    remain := len(x.out) - x.outUsed
    if remain > x.outUsed {
        return
    }

    copy(x.out, x.out[x.outUsed:])

    x.out = x.out[:cap(x.out)]
    for remain < len(x.out)-bs {
        x.b.Encrypt(x.cipher, x.cipher)

        copy(x.out[remain:], x.cipher)

        remain += bs
    }

    x.out = x.out[:remain]
    x.outUsed = 0
}

func (x *nofb) XORKeyStream(dst, src []byte) {
    if len(dst) < len(src) {
        panic("cipher/nofb: output smaller than input")
    }

    if alias.InexactOverlap(dst[:len(src)], src) {
        panic("cipher/nofb: invalid buffer overlap")
    }

    bs := x.b.BlockSize()
    for i := 0; i < len(src); i += bs {
        if x.outUsed >= len(x.out)-x.b.BlockSize() {
            x.refill()
        }

        end := i + bs
        if end > len(src) {
            end = len(src)
        }

        dstBytes := make([]byte, end-i)
        srcBytes := src[i:end]

        subtle.XORBytes(dstBytes, srcBytes, x.out[x.outUsed:])

        copy(dst[i:end], dstBytes)

        x.outUsed += bs
    }
}
