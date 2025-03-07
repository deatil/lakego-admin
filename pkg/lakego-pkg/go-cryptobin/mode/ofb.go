// OFB (Output Feedback) Mode.
package mode

import (
    "crypto/subtle"
    "crypto/cipher"

    "github.com/deatil/go-cryptobin/tool/alias"
)

type ofb struct {
    b       cipher.Block
    cipher  []byte
    out     []byte
    outUsed int
}

// NewOFB returns a Stream that encrypts or decrypts using the block cipher b
// in output feedback mode. The initialization vector iv's length must be equal
// to b's block size.
func NewOFB(b cipher.Block, iv []byte) cipher.Stream {
    blockSize := b.BlockSize()
    if len(iv) != blockSize {
        panic("cipher.NewOFB: IV length must equal block size")
    }

    bufSize := streamBufferSize
    if bufSize < blockSize {
        bufSize = blockSize
    }

    x := &ofb{
        b:       b,
        cipher:  make([]byte, blockSize),
        out:     make([]byte, 0, bufSize),
        outUsed: 0,
    }

    copy(x.cipher, iv)
    return x
}

func (x *ofb) refill() {
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

func (x *ofb) XORKeyStream(dst, src []byte) {
    if len(dst) < len(src) {
        panic("go-cryptobin/ofb: output smaller than input")
    }
    if alias.InexactOverlap(dst[:len(src)], src) {
        panic("go-cryptobin/ofb: invalid buffer overlap")
    }

    for len(src) > 0 {
        if x.outUsed >= len(x.out)-x.b.BlockSize() {
            x.refill()
        }

        n := subtle.XORBytes(dst, src, x.out[x.outUsed:])
        dst = dst[n:]
        src = src[n:]
        x.outUsed += n
    }
}
