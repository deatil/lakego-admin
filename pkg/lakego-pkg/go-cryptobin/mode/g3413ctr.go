package mode

import (
    "crypto/cipher"
    "crypto/subtle"

    "github.com/deatil/go-cryptobin/tool/alias"
)

/**
 * implements the GOST 3412 2015 CTR counter mode (GCTR).
 */
type g3413ctr struct {
    b       cipher.Block
    ctr     []byte
    out     []byte
    outUsed int
    s       int
}

const g3413StreamBufferSize = 512

// g3413ctrAble is an interface implemented by ciphers that have a specific optimized
// implementation of CTR, like crypto/aes. NewCTR will check for this interface
// and return the specific Stream if found.
type g3413ctrAble interface {
    NewG3413CTR(iv []byte) cipher.Stream
}

// NewCTR returns a Stream which encrypts/decrypts using the given Block in
// counter mode. The length of iv must be the same as the Block's block size.
func NewG3413CTR(block cipher.Block, iv []byte) cipher.Stream {
    return NewG3413CTRWithBitBlockSize(block, iv, block.BlockSize() * 8)
}

// NewG3413CTRWithBitBlockSize returns a Stream which encrypts/decrypts using the given Block in
// counter mode. The length of iv must be the same as the Block's block size.
func NewG3413CTRWithBitBlockSize(block cipher.Block, iv []byte, bitBlockSize int) cipher.Stream {
    if ctr, ok := block.(g3413ctrAble); ok {
        return ctr.NewG3413CTR(iv)
    }

    bs := block.BlockSize()

    if len(iv) != (bs / 2) {
        panic("cryptobin/g3413ctr.NewG3413CTRWithBitBlockSize: Parameter IV length must be == blockSize/2")
    }

    bufSize := g3413StreamBufferSize
    if bufSize < block.BlockSize() {
        bufSize = block.BlockSize()
    }

    x := &g3413ctr{
        b:       block,
        ctr:     make([]byte, bs),
        out:     make([]byte, 0, bufSize),
        outUsed: 0,
        s:       bitBlockSize / 8,
    }

    copy(x.ctr, iv)

    return x
}

func (x *g3413ctr) refill() {
    remain := len(x.out) - x.outUsed

    copy(x.out, x.out[x.outUsed:])

    x.out = x.out[:cap(x.out)]
    bs := x.s

    out := make([]byte, x.b.BlockSize())

    for remain <= len(x.out)-bs {
        x.b.Encrypt(out, x.ctr)

        copy(x.out[remain:], out[:bs])

        remain += bs

        // Increment counter
        for i := len(x.ctr) - 1; i >= 0; i-- {
            x.ctr[i]++
            if x.ctr[i] != 0 {
                break
            }
        }
    }

    x.out = x.out[:remain]
    x.outUsed = 0
}

func (x *g3413ctr) XORKeyStream(dst, src []byte) {
    if len(dst) < len(src) {
        panic("cryptobin/g3413ctr: output smaller than input")
    }
    if alias.InexactOverlap(dst[:len(src)], src) {
        panic("cryptobin/g3413ctr: invalid buffer overlap")
    }

    for len(src) > 0 {
        if x.outUsed >= len(x.out)-x.s {
            x.refill()
        }

        n := subtle.XORBytes(dst, src, x.out[x.outUsed:x.outUsed+x.s])

        dst = dst[n:]
        src = src[n:]

        x.outUsed += n
    }
}
