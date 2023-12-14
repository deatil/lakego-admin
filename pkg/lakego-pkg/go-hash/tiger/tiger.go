package tiger

import (
    "hash"
    "encoding/binary"
)

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

func (this *digest) Size() int {
    return Size
}

func (this *digest) BlockSize() int {
    return BlockSize
}

func (this *digest) Reset() {
    this.a = initA
    this.b = initB
    this.c = initC
    this.nx = 0
    this.length = 0
}

func (this *digest) Write(p []byte) (length int, err error) {
    length = len(p)

    this.length += uint64(length)

    if this.nx > 0 {
        n := len(p)
        if n > chunk-this.nx {
            n = chunk - this.nx
        }

        copy(this.x[this.nx:this.nx+n], p[:n])
        this.nx += n

        if this.nx == chunk {
            this.compress(this.x[:chunk])
            this.nx = 0
        }

        p = p[n:]
    }

    for len(p) >= chunk {
        this.compress(p[:chunk])
        p = p[chunk:]
    }

    if len(p) > 0 {
        this.nx = copy(this.x[:], p)
    }

    return
}

func (this *digest) Sum(in []byte) []byte {
    var tmp [64]byte

    if this.ver == 1 {
        tmp[0] = 0x01
    } else {
        tmp[0] = 0x80
    }

    length := this.length

    size := length & 0x3f
    if size < 56 {
        this.Write(tmp[:56-size])
    } else {
        this.Write(tmp[:64+56-size])
    }

    length <<= 3
    for i := uint(0); i < 8; i++ {
        tmp[i] = byte(length >> (8 * i))
    }

    this.Write(tmp[:8])

    for i := uint(0); i < 8; i++ {
        tmp[i] = byte(this.a >> (8 * i))
        tmp[i+8] = byte(this.b >> (8 * i))
        tmp[i+16] = byte(this.c >> (8 * i))
    }

    return append(in, tmp[:24]...)
}

func (this *digest) compress(data []byte) {
    a := this.a
    b := this.b
    c := this.c

    var x []uint64
    if littleEndian {
        x = []uint64{
            binary.LittleEndian.Uint64(data[0:]),
            binary.LittleEndian.Uint64(data[8:]),
            binary.LittleEndian.Uint64(data[16:]),
            binary.LittleEndian.Uint64(data[24:]),
            binary.LittleEndian.Uint64(data[32:]),
            binary.LittleEndian.Uint64(data[40:]),
            binary.LittleEndian.Uint64(data[48:]),
            binary.LittleEndian.Uint64(data[56:]),
        }
    } else {
        x = []uint64{
            binary.BigEndian.Uint64(data[0:]),
            binary.BigEndian.Uint64(data[8:]),
            binary.BigEndian.Uint64(data[16:]),
            binary.BigEndian.Uint64(data[24:]),
            binary.BigEndian.Uint64(data[32:]),
            binary.BigEndian.Uint64(data[40:]),
            binary.BigEndian.Uint64(data[48:]),
            binary.BigEndian.Uint64(data[56:]),
        }
    }

    this.a, this.b, this.c = pass(this.a, this.b, this.c, x, 5)

    keySchedule(x)
    this.c, this.a, this.b = pass(this.c, this.a, this.b, x, 7)

    keySchedule(x)
    this.b, this.c, this.a = pass(this.b, this.c, this.a, x, 9)

    this.a ^= a
    this.b -= b
    this.c += c
}
