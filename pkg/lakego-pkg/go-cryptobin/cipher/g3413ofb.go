package cipher

import (
    "crypto/cipher"
    "crypto/subtle"

    "github.com/deatil/go-cryptobin/tool/alias"
)

/**
 * An implementation of the OFB mode for GOST 3412 2015 cipher.
 * See  <a href="https://www.tc26.ru/standard/gost/GOST_R_3413-2015.pdf">GOST R 3413 2015</a>
 */
type g3413ofb struct {
    b       cipher.Block
    cipher  []byte
    y       []byte
    out     []byte
    outUsed int
}

// NewG3413OFB returns a Stream that encrypts or decrypts using the block cipher b
// in output feedback mode. The initialization vector iv's length must be equal
// to b's block size.
func NewG3413OFB(b cipher.Block, iv []byte) cipher.Stream {
    blockSize := b.BlockSize()
    if len(iv) != 2*blockSize {
        panic("cryptobin/g3413ofb.NewG3413OFB: IV length must equal two block size")
    }

    bufSize := streamBufferSize
    if bufSize < blockSize {
        bufSize = blockSize
    }

    x := &g3413ofb{
        b:       b,
        cipher:  make([]byte, 2*blockSize),
        y:       make([]byte, blockSize),
        out:     make([]byte, 0, bufSize),
        outUsed: 0,
    }

    copy(x.cipher, iv)
    return x
}

func (x *g3413ofb) refill() {
    bs := x.b.BlockSize()
    remain := len(x.out) - x.outUsed
    if remain > x.outUsed {
        return
    }

    copy(x.out, x.out[x.outUsed:])

    x.out = x.out[:cap(x.out)]
    for remain < len(x.out)-bs {
        x.b.Encrypt(x.y, x.cipher[:bs])

        copy(x.out[remain:], x.y)

        copy(x.cipher, x.cipher[bs:])
        copy(x.cipher[bs:], x.y)

        remain += bs
    }

    x.out = x.out[:remain]
    x.outUsed = 0
}

func (x *g3413ofb) XORKeyStream(dst, src []byte) {
    if len(dst) < len(src) {
        panic("cryptobin/g3413ofb: output smaller than input")
    }
    if alias.InexactOverlap(dst[:len(src)], src) {
        panic("cryptobin/g3413ofb: invalid buffer overlap")
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
