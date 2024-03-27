package kupyna

import (
    "hash"
)

// kmac256 represents the partial evaluation of a checksum.
type kmac256 struct {
    h hash.Hash
    ik [32]byte
    len uint64
}

// NewKmac256 returns a new hash.Hash computing the kmac256 checksum
func NewKmac256(key []byte) (hash.Hash, error) {
    l := len(key)
    if l != 32 {
        return nil, KeySizeError(l)
    }

    d := new(kmac256)
    d.h = New256()
    d.init(key)

    return d, nil
}

func (d *kmac256) init(key []byte) {
    d.h.Write(key)
    d.h.Write(kpad32[:])

    d.len = 0
    for i := 0; i < 32; i++ {
        d.ik[i] = ^key[i]
    }
}

func (d *kmac256) Reset() {
    d.h.Reset()
}

func (d *kmac256) Size() int {
    return d.h.Size()
}

func (d *kmac256) BlockSize() int {
    return d.h.BlockSize()
}

func (d *kmac256) Write(p []byte) (nn int, err error) {
    d.len += uint64(len(p))
    return d.h.Write(p)
}

func (d *kmac256) Sum(in []byte) []byte {
    // Make a copy of d so that caller can keep writing and summing.
    d0 := *d
    hash := d0.checkSum()
    return append(in, hash...)
}

func (d *kmac256) checkSum() []byte {
    var n uint64 = d.len
    var pad_size uint64

    if n < 52 {
        pad_size = 51 - n
    } else {
        pad_size = 63 - ((n - 52) % 64)
    }

    n = n * 8

    d.h.Write(dpad[:pad_size + 1])

    nbytes := uint64sToBytes([]uint64{n})
    d.h.Write(nbytes)

    d.h.Write(dpad[16:20])
    d.h.Write(d.ik[:])

    hash := d.h.Sum(nil)
    return hash
}
