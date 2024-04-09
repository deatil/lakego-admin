package chaskey

import (
    "fmt"
)

// The size of an chaskey checksum in bytes.
const Size = 16

// The blocksize of chaskey in bytes.
const BlockSize = 16

const KeySize   = 16

type KeySizeError int

func (k KeySizeError) Error() string {
    return fmt.Sprintf("go-hash/chaskey: invalid key size %d", int(k))
}

// digest represents the partial evaluation of a checksum.
type digest struct {
    s   [4]uint32
    x   [BlockSize]byte
    nx  int
    len uint64

    k1  [4]uint32
    k2  [4]uint32
    r   int
}

func newDigest(key []byte, rounds int) (*digest, error) {
    l := len(key)
    if l != KeySize {
        return nil, KeySizeError(l)
    }

    d := new(digest)
    d.Reset()
    d.r = rounds
    d.expandKey(key)

    return d, nil
}

func (d *digest) Reset() {
    d.s = [4]uint32{}
    d.x = [BlockSize]byte{}
    d.nx = 0
    d.len = 0

    d.k1 = [4]uint32{}
    d.k2 = [4]uint32{}
}

func (d *digest) Size() int {
    return Size
}

func (d *digest) BlockSize() int {
    return BlockSize
}

func (d *digest) Write(p []byte) (nn int, err error) {
    nn = len(p)

    d.len += uint64(nn)
    if d.nx > 0 {
        n := copy(d.x[d.nx:], p)
        d.nx += n
        if d.nx == BlockSize {
            block(d, d.x[:])
            d.nx = 0
        }

        p = p[n:]
    }

    for ; len(p) > BlockSize; p = p[BlockSize:] {
        block(d, p)
        d.nx = 0
    }

    if len(p) > 0 {
        d.nx = copy(d.x[:], p)
    }

    return
}

func (d *digest) Sum(in []byte) []byte {
    // Make a copy of d so that caller can keep writing and summing.
    d0 := *d
    hash := d0.checkSum()
    return append(in, hash[:]...)
}

func (d *digest) checkSum() (out [Size]byte) {
    lastblock(d)

    if d.nx != 0 {
        panic("d.nx != 0")
    }

    digest := uint32sToBytes(d.s[:])
    copy(out[:], digest)

    return
}

func (d *digest) expandKey(key []byte) {
    k := bytesToUint32s(key)
    copy(d.s[:], k)

    timestwo(d.k1[:], k[:])
    timestwo(d.k2[:], d.k1[:])
}
