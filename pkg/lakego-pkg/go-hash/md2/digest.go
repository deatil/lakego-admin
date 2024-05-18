package md2

import (
    "bytes"
)

const (
    // The size of an MD2 checksum in bytes.
    Size = 16

    // The blocksize of MD2 in bytes.
    BlockSize = 16
)

// digest represents the partial evaluation of a checksum.
type digest struct {
    s   [48]byte        // state, 48 ints
    x   [BlockSize]byte // temp storage buffer, 16 bytes
    nx  int             // how many bytes are there in the buffer
    len uint64

    digest [Size]byte // the digest, Size
}

func newDigest() *digest {
    d := new(digest)
    d.Reset()
    return d
}

func (d *digest) Reset() {
    d.s = [48]byte{}
    d.x = [BlockSize]byte{}
    d.nx = 0
    d.len = 0

    d.digest = [Size]byte{}
}

func (d *digest) Size() int {
    return Size
}

func (d *digest) BlockSize() int {
    return BlockSize
}

// Write is the interface for IO Writer
func (d *digest) Write(p []byte) (nn int, err error) {
    nn = len(p)

    plen := len(p)

    for d.nx + plen >= BlockSize {
        xx := BlockSize - d.nx

        copy(d.x[d.nx:], p)

        d.block(d.x[:])

        plen -= xx
        d.len += uint64(xx)

        p = p[xx:]
        d.nx = 0
    }

    copy(d.x[d.nx:], p)
    d.nx += plen
    d.len += uint64(plen)

    return
}

func (d *digest) Sum(in []byte) []byte {
    // Make a copy of d so that caller can keep writing and summing.
    d0 := *d
    hash := d0.checkSum()
    return append(in, hash[:]...)
}

func (d *digest) checkSum() []byte {
    padding := BlockSize - d.nx
    tmp := bytes.Repeat([]byte{byte(padding)}, padding)
    d.Write(tmp)

    // At this state we should have nothing left in buffer
    if d.nx != 0 {
        panic("d.nx != 0")
    }

    d.Write(d.digest[:])

    // At this state we should have nothing left in buffer
    if d.nx != 0 {
        panic("d.nx != 0")
    }

    return d.s[:16]
}

func (d *digest) block(p []byte) {
    var t, i, j uint8
    t = 0

    for i = 0; i < 16; i++ {
        d.s[i+16] = p[i]
        d.s[i+32] = byte(p[i] ^ d.s[i])
    }

    for i = 0; i < 18; i++ {
        for j = 0; j < 48; j++ {
            d.s[j] = byte(d.s[j] ^ sbox[t])
            t = d.s[j]
        }
        t = byte(t + i)
    }

    t = d.digest[15]

    for i = 0; i < 16; i++ {
        d.digest[i] = byte(d.digest[i] ^ sbox[p[i]^t])
        t = d.digest[i]
    }
}

