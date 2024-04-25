package groestl

import (
    "hash"
    "errors"
)

const (
    // hash size
    Size224 = 28
    Size256 = 32
    Size384 = 48
    Size512 = 64
)

// digest represents the partial evaluation of a checksum.
type digest struct {
    s   [16]uint64
    x   [128]byte
    nx  int
    len uint64

    hs, bs int
}

// New returns a new hash.Hash computing the Groestl checksum
func New(hashsize int) (hash.Hash, error) {
    if hashsize == 0 {
        return nil, errors.New("go-hash/groestl: hash size can't be zero")
    }
    if (hashsize % 8) > 0 {
        return nil, errors.New("go-hash/groestl: non-byte hash sizes are not supported")
    }
    if hashsize > 512 {
        return nil, errors.New("go-hash/groestl: invalid hash size")
    }

    d := new(digest)
    d.hs = hashsize
    d.Reset()

    return d, nil
}

func (d *digest) Reset() {
    if d.hs > 256 {
        d.bs = 1024
    } else {
        d.bs = 512
    }

    d.nx = 0
    d.len = 0

    // m
    d.x = [128]byte{}

    // h
    d.s = [16]uint64{}

    if d.hs > 256 {
        d.s[15] = swap_uint64(uint64(d.hs))
    } else {
        d.s[7] = swap_uint64(uint64(d.hs))
    }
}

func (d *digest) Size() int {
    return d.hs / 8
}

func (d *digest) BlockSize() int {
    return d.bs / 8
}

func (d *digest) Write(p []byte) (nn int, err error) {
    nn = len(p)

    plen := len(p)

    var limit = d.bs / 8
    for d.nx + plen >= limit {
        xx := limit - d.nx

        copy(d.x[d.nx:], p)

        d.transform()

        plen -= xx
        d.len += uint64(xx) * 8

        p = p[xx:]
        d.nx = 0
    }

    copy(d.x[d.nx:], p)
    d.nx += plen
    d.len += uint64(plen) * 8

    return
}

func (d *digest) Sum(in []byte) []byte {
    // Make a copy of d so that caller can keep writing and summing.
    d0 := *d
    hash := d0.checkSum()
    return append(in, hash...)
}

func (d *digest) checkSum() []byte {
    d.x[d.nx] = 0x80
    d.nx++

    d.len += 8

    var limit = d.bs / 8

    zeros := make([]byte, limit)

    if d.nx > limit - 8 {
        copy(d.x[d.nx:], zeros)
        d.transform()

        d.len += uint64(d.bs) - uint64(d.nx) * 8
        d.nx = 0
    }

    copy(d.x[d.nx:], zeros)
    d.len += uint64(d.bs) - uint64(d.nx) * 8

    var mlen uint64 = swap_uint64(d.len / uint64(d.bs))

    PUTU64(d.x[limit - 8:], mlen)

    d.transform()
    d.outputTransform()

    ss := uint64sToBytes(d.s[:])
    return ss[limit - d.hs / 8:limit]
}

func (d *digest) transform() {
    xx := bytesToUint64s(d.x[:])

    if d.bs == 512 {
        transform256(&d.s, xx)
    } else {
        transform512(&d.s, xx)
    }
}

func (d *digest) outputTransform() {
    if d.bs == 512 {
        outputTransform256(&d.s)
    } else {
        outputTransform512(&d.s)
    }
}
