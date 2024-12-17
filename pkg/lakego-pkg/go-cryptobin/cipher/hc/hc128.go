package hc

import (
    "crypto/cipher"

    "github.com/deatil/go-cryptobin/tool/alias"
)

type hcCipher128 struct {
    block_ [16]uint32
    P [512]uint32
    Q [512]uint32
    X [16]uint32
    Y [16]uint32
    words uint32
    pos int
}

// NewCipher128 creates and returns a new cipher.Stream.
func NewCipher128(key, iv []byte) (cipher.Stream, error) {
    if len(key) != 16 {
        return nil, KeySizeError(len(key))
    }
    if len(iv) != 16 {
        return nil, IVSizeError(len(iv))
    }

    c := new(hcCipher128)
    c.expandKey(key, iv)

    return c, nil
}

func (this *hcCipher128) XORKeyStream(dst, src []byte) {
    if len(src) == 0 {
        return
    }

    if len(dst) < len(src) {
        panic("go-cryptobin/hc: output smaller than input")
    }
    if alias.InexactOverlap(dst[:len(src)], src) {
        panic("go-cryptobin/hc: invalid buffer overlap")
    }

    this.crypt(dst, src)
}

func (this *hcCipher128) crypt(out, in []byte) {
    var i int = 0
    var l int = len(in)

    blocks := uint32sToBytes(this.block_[:])

    if this.pos > 0 {
        for i < l && this.pos < 64 {
            out[i] = in[i] ^ blocks[this.pos]
            this.pos++
            i++
        }

        l -= i
    }

    if l > 0 {
        this.pos = 0
    }

    for ; l > 0; l -= tmin(64, l) {
        generate_block_128_block(this.P[:], this.Q[:], this.X[:], this.Y[:], this.block_[:], &this.words)
        blocks = uint32sToBytes(this.block_[:])

        if l >= 64 {
            xor_block_512(in[i:], blocks, out[i:])
            i += 64
        } else {
            for ; this.pos < l; this.pos++ {
                out[i] = in[i] ^ blocks[this.pos]
                i++
            }
        }
    }
}

func (this *hcCipher128) expandKey(key, iv []byte) {
    keys := bytesToUint32s(key)
    ivs := bytesToUint32s(iv)

    var W [1280]uint32
    W[0] = keys[0]
    W[1] = keys[1]
    W[2] = keys[2]
    W[3] = keys[3]
    W[4] = keys[0]
    W[5] = keys[1]
    W[6] = keys[2]
    W[7] = keys[3]
    W[8] = ivs[0]
    W[9] = ivs[1]
    W[10] = ivs[2]
    W[11] = ivs[3]
    W[12] = ivs[0]
    W[13] = ivs[1]
    W[14] = ivs[2]
    W[15] = ivs[3]

    var i uint32
    for i = 16; i < 1280; i++ {
        W[i] = f2(W[i - 2]) + W[i - 7] + f1(W[i - 15]) + W[i - 16] + i
    }

    copy(this.P[:], W[256:])
    copy(this.Q[:], W[768:])
    copy(this.X[:], this.P[512 - 16:])
    copy(this.Y[:], this.Q[512 - 16:])

    this.words = 0
    this.pos = 0
    for i = 0; i < 1024 / 16; i++ {
        generate_block_128(this.P[:], this.Q[:], this.X[:], this.Y[:], &this.words)
    }
}
