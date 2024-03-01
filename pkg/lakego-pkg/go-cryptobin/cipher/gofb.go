// implements the GOST 28147 OFB counter mode (GCTR).
package cipher

import (
    "crypto/cipher"
    "crypto/subtle"
    "encoding/binary"

    "github.com/deatil/go-cryptobin/tool/alias"
)

/**
 * implements the GOST 28147 OFB counter mode (GCTR).
 */
type gofb struct {
    b       cipher.Block
    cipher  []byte
    out     []byte
    outUsed int
    C1      int32
    C2      int32
    N3      int32
    N4      int32
}

// NewGOFB returns a Stream that encrypts or decrypts using the block cipher b
// in output feedback mode. The initialization vector iv's length must be equal
// to b's block size.
func NewGOFB(b cipher.Block, iv []byte) cipher.Stream {
    blockSize := b.BlockSize()
    if len(iv) != blockSize {
        panic("cryptobin/gofb.NewGOFB: IV length must equal block size")
    }

    bufSize := streamBufferSize
    if bufSize < blockSize {
        bufSize = blockSize
    }

    x := &gofb{
        b:       b,
        cipher:  make([]byte, blockSize),
        out:     make([]byte, 0, bufSize),
        outUsed: 0,
        C1:      16843012, // 00000001000000010000000100000100
        C2:      16843009, // 00000001000000010000000100000001
    }

    copy(x.cipher, iv)
    return x
}

func (x *gofb) refill() {
    bs := x.b.BlockSize()
    remain := len(x.out) - x.outUsed
    if remain > x.outUsed {
        return
    }

    copy(x.out, x.out[x.outUsed:])

    x.out = x.out[:cap(x.out)]
    for remain < len(x.out)-bs {
        x.N3 += x.C2
        x.N4 += x.C1

        if x.N4 < x.C1 { // addition is mod (2**32 - 1)
            if x.N4 > 0 {
                x.N4++
            }
        }

        binary.LittleEndian.PutUint32(x.cipher[0:], uint32(x.N3))
        binary.LittleEndian.PutUint32(x.cipher[4:], uint32(x.N4))

        x.b.Encrypt(x.cipher, x.cipher)

        copy(x.out[remain:], x.cipher)

        remain += bs
    }

    x.out = x.out[:remain]
    x.outUsed = 0
}

func (x *gofb) XORKeyStream(dst, src []byte) {
    if len(dst) < len(src) {
        panic("cryptobin/gofb: output smaller than input")
    }

    if alias.InexactOverlap(dst[:len(src)], src) {
        panic("cryptobin/gofb: invalid buffer overlap")
    }

    ofbOutV := make([]byte, x.b.BlockSize())
    x.b.Encrypt(ofbOutV, x.cipher)

    x.N3 = int32(binary.LittleEndian.Uint32(ofbOutV[0:]))
    x.N4 = int32(binary.LittleEndian.Uint32(ofbOutV[4:]))

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
