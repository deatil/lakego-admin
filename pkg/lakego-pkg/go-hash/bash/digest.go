package bash

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
    s   [24]uint64
    x   []byte
    nx  int
    len uint64

    hs, bs int
}

// New returns a new hash.Hash computing the bash checksum
func New(hashsize int) (hash.Hash, error) {
    if hashsize == 0 {
        return nil, errors.New("go-hash/bash: hash size can't be zero")
    }
    if (hashsize % 8) > 0 {
        return nil, errors.New("go-hash/bash: non-byte hash sizes are not supported")
    }
    if hashsize > 512 {
        return nil, errors.New("go-hash/bash: invalid hash size")
    }

    d := new(digest)
    d.hs = hashsize / 8
    d.bs = (BASH_SLICES_X * BASH_SLICES_Y * 8) - (2 * d.hs)

    d.Reset()

    return d, nil
}

func (d *digest) Reset() {
    d.x = make([]byte, 24 * 8)
    d.s = [24]uint64{}
    d.nx = 0
    d.len = 0

    /* Put <l / 4>64 at the end of the state */
    state := uint64sToBytes(d.s[:])
    state[(BASH_SLICES_X * BASH_SLICES_Y * 8) - 8] = byte(d.hs)
    ss := bytesToUint64s(state)
    copy(d.s[:], ss)
}

func (d *digest) Size() int {
    return d.hs
}

func (d *digest) BlockSize() int {
    return d.bs
}

func (d *digest) Write(p []byte) (nn int, err error) {
    nn = len(p)

    d.len += uint64(nn)

    plen := len(p)

    for d.nx + plen >= d.bs {
        copy(d.x[d.nx:], p)

        d.processBlock(d.x)

        xx := d.bs - d.nx
        plen -= xx

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
    zeros := make([]byte, d.bs)
    copy(d.x[d.nx:], zeros)

    d.x[d.nx] = 0x40

    d.processBlock(d.x[:])

    state := uint64sToBytes(d.s[:])
    return state[:d.hs]
}

func (d *digest) processBlock(data []byte) {
    state := bytesToUint64s(data)

    // get xor from state and new data
    for k, v := range d.s {
        d.s[k] = v ^ state[k]
    }

    BASHF(d.s[:], true)
}
