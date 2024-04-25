package esch

import (
    "hash"
    "errors"
)

const (
    // hash size
    Size256 = 32
    Size384 = 48
)

// The blocksize of chaskey in bytes.
const BlockSize = 16

// digest represents the partial evaluation of a checksum.
type digest struct {
    s   [16]uint32
    x   [128]byte
    nx  int
    len uint64

    hs, bs int
}

// New returns a new hash.Hash computing the ESCH checksum
func New(hashsize int) (hash.Hash, error) {
    if hashsize == 0 {
        return nil, errors.New("go-hash/esch: hash size can't be zero")
    }
    if hashsize != 256 && hashsize != 384 {
        return nil, errors.New("go-hash/esch: invalid hash size")
    }

    d := new(digest)
    d.hs = hashsize
    d.Reset()

    return d, nil
}

func (d *digest) Reset() {
    d.bs = 128

    // h
    d.s = [16]uint32{}

    // m
    d.x = [128]byte{}

    d.nx = 0
    d.len = 0
}

func (d *digest) Size() int {
    return d.hs / 8
}

func (d *digest) BlockSize() int {
    return BlockSize
}

func (d *digest) Write(p []byte) (nn int, err error) {
    nn = len(p)

    plen := len(p)

    const bss int = 16
    if d.nx > 0 && d.nx + plen >= bss {
        xx := bss - d.nx

        copy(d.x[d.nx:], p)

        d.transform(d.x[:], 1, false)

        plen -= xx
        p = p[xx:]

        d.len += uint64(xx) * 8
        d.nx = 0
    }

    if plen > 16  {
        blocks := (plen - 1) / bss
        bytes := blocks * bss

        d.transform(p[:bytes], blocks, false)

        plen -= bytes
        p = p[bytes:]
        d.len += uint64(bytes) * 8
    }

    copy(d.x[d.nx:], p)
    d.nx += plen

    return
}

func (d *digest) Sum(in []byte) []byte {
    // Make a copy of d so that caller can keep writing and summing.
    d0 := *d
    hash := d0.checkSum()
    return append(in, hash...)
}

func (d *digest) checkSum() []byte {
    zeros := make([]byte, 128)

    var processed int = 0
    d.len = 1
    if d.nx < 16 {
        copy(d.x[d.nx:], zeros)
        d.x[d.nx] = 0x80
        d.s[(d.hs+128)/64 - 1] ^= 0x1000000
    } else {
        d.s[(d.hs+128)/64 - 1] ^= 0x2000000
    }

    d.transform(d.x[:], 1, true)

    var hss int = d.hs / 8
    var r, ns int
    var xx, out []byte

    for processed < hss {
        if d.len == 0 {
            if d.hs > 256 {
                r = 8
                ns = 8
            } else {
                r = 6
                ns = 7
            }

            sparkle(&d.s, r, ns)
        }

        d.nx = tmin(hss - processed, 16)

        xx = uint32sToBytes(d.s[:])
        out = append(out, xx[:d.nx]...)

        processed += d.nx
        d.len = 0
    }

    return out
}

func (d *digest) transform(data []byte, num_blks int, lastBlock bool) {
    var blk, steps, r, i int
    var M [4]uint32
    var x, y uint32

    datas := bytesToUint32s(data[:])

    for blk = 0; blk < num_blks; blk++ {
        for i = 0; i < 4; i++ {
            M[i] = datas[blk * 4 + i]
        }

        x = M[0] ^ M[2]
        y = M[1] ^ M[3]

        x = rotater32(x ^ (x << 16), 16)
        y = rotater32(y ^ (y << 16), 16)

        d.s[0] = d.s[0] ^ M[0] ^ y
        d.s[1] = d.s[1] ^ M[1] ^ x
        d.s[2] = d.s[2] ^ M[2] ^ y
        d.s[3] = d.s[3] ^ M[3] ^ x
        d.s[4] ^= y
        d.s[5] ^= x

        if d.hs > 256 {
            d.s[6] ^= y
            d.s[7] ^= x
        }

        if lastBlock {
            steps = 11
        } else {
            steps = 7
        }

        if d.hs > 256 {
            steps++
        }

        if d.hs > 256 {
            r = 8
        } else {
            r = 6
        }

        sparkle(&d.s, r, steps)
    }
}
