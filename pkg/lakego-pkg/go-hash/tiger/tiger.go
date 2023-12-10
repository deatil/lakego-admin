package tiger

import "hash"

// The size of a Tiger hash value in bytes
const Size = 24

// The blocksize of Tiger hash function in bytes
const BlockSize = 64

const (
    chunk = 64
    initA = 0x0123456789abcdef
    initB = 0xfedcba9876543210
    initC = 0xf096a5b4c3b2e187
)

type digest struct {
    a      uint64
    b      uint64
    c      uint64
    x      [chunk]byte
    nx     int
    length uint64
    ver    int
}

func (d *digest) Reset() {
    d.a = initA
    d.b = initB
    d.c = initC
    d.nx = 0
    d.length = 0
}

// New returns a new hash.Hash computing the Tiger hash value
func New() hash.Hash {
    d := new(digest)
    d.Reset()
    d.ver = 1
    return d
}

// New returns a new hash.Hash computing the Tiger2 hash value
func New2() hash.Hash {
    d := new(digest)
    d.Reset()
    d.ver = 2
    return d
}

func (d *digest) BlockSize() int {
    return BlockSize
}

func (d *digest) Size() int {
    return Size
}

func (d *digest) Write(p []byte) (length int, err error) {
    length = len(p)

    d.length += uint64(length)

    if d.nx > 0 {
        n := len(p)
        if n > chunk-d.nx {
            n = chunk - d.nx
        }

        copy(d.x[d.nx:d.nx+n], p[:n])
        d.nx += n

        if d.nx == chunk {
            d.compress(d.x[:chunk])
            d.nx = 0
        }

        p = p[n:]
    }

    for len(p) >= chunk {
        d.compress(p[:chunk])
        p = p[chunk:]
    }

    if len(p) > 0 {
        d.nx = copy(d.x[:], p)
    }

    return
}

func (d digest) Sum(in []byte) []byte {
    length := d.length
    var tmp [64]byte
    if d.ver == 1 {
        tmp[0] = 0x01
    } else {
        tmp[0] = 0x80
    }

    size := length & 0x3f
    if size < 56 {
        d.Write(tmp[:56-size])
    } else {
        d.Write(tmp[:64+56-size])
    }

    length <<= 3
    for i := uint(0); i < 8; i++ {
        tmp[i] = byte(length >> (8 * i))
    }
    d.Write(tmp[:8])

    for i := uint(0); i < 8; i++ {
        tmp[i] = byte(d.a >> (8 * i))
        tmp[i+8] = byte(d.b >> (8 * i))
        tmp[i+16] = byte(d.c >> (8 * i))
    }

    return append(in, tmp[:24]...)
}
