package streebog

import (
    "errors"
)

// GOST R 34.11-2012 hash function.
// RFC 6986.

const (
    // hash size
    Size256 = 32
    Size512 = 64

    BlockSize = 64
)

// digest represents the partial evaluation of a checksum.
type digest struct {
    s   [8]uint64
    x   [BlockSize]byte
    nx  int
    len uint64

    S  [8]uint64
    hs int
}

// newDigest returns a new *digest computing the Streebog checksum
func newDigest(hashsize int) (*digest, error) {
    switch hashsize {
        case 256, 512:
            break
        default:
            return nil, errors.New("go-hash/streebog: invalid hash size")
    }

    d := new(digest)
    d.hs = hashsize
    d.Reset()

    return d, nil
}

func (d *digest) Reset() {
    d.nx = 0
    d.len = 0

    // m
    d.x = [BlockSize]byte{}

    // h
    d.s = [8]uint64{}

    if d.hs == 512 {
        d.s = initIv512
    } else {
        d.s = initIv256
    }

    d.S = [8]uint64{}
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

    var limit = BlockSize
    for d.nx + plen >= limit {
        xx := limit - d.nx

        copy(d.x[d.nx:], p)

        d.transform(false)

        plen -= xx
        d.len += 512

        p = p[xx:]
        d.nx = 0
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
    d.x[d.nx] = 0x01
    d.nx++

    zeros := [BlockSize]byte{}

    copy(d.x[d.nx:], zeros[:])
    d.transform(false)
    d.len += uint64(d.nx - 1) * 8

    copy(d.x[:], zeros[:])
    PUTU64(d.x[:], d.len)
    d.transform(true)

    SS := uint64sToBytes(d.S[:])
    copy(d.x[:], SS)
    d.transform(true)

    ss := uint64sToBytes(d.s[8 - d.hs/BlockSize:])
    return ss[:d.hs / 8]
}

func (d *digest) transform(last bool) {
    if last {
        gN(&d.s, d.x[:], 0)
    } else {
        gN(&d.s, d.x[:], d.len)
    }

    if !last {
        addm(d.x[:], &d.S)
    }
}
