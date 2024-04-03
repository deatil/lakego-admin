package tiger

import (
    "hash"
)

// The size list of a Tiger hash value in bytes
const Size128 = 16
const Size160 = 20
const Size192 = 24

// The blocksize of Tiger hash function in bytes
const BlockSize = 64

var (
    initH = [3]uint64{
        0x0123456789abcdef,
        0xfedcba9876543210,
        0xf096a5b4c3b2e187,
    }
)

type digest struct {
    s      [3]uint64
    x      [BlockSize]byte
    nx     int
    length uint64

    hs  int
    ver int
}

// newDigest returns a new hash.Hash computing the Tiger hash value
func newDigest(hs int) hash.Hash {
    d := new(digest)
    d.Reset()
    d.hs = hs
    d.ver = 1
    return d
}

// newDigest2 returns a new hash.Hash computing the Tiger2 hash value
func newDigest2(hs int) hash.Hash {
    d := new(digest)
    d.Reset()
    d.hs = hs
    d.ver = 2
    return d
}

func (this *digest) Size() int {
    return this.hs
}

func (this *digest) BlockSize() int {
    return BlockSize
}

func (this *digest) Reset() {
    this.s = initH
    this.nx = 0
    this.length = 0
}

func (this *digest) Write(p []byte) (length int, err error) {
    length = len(p)

    this.length += uint64(length)

    if this.nx > 0 {
        n := len(p)
        if n > BlockSize-this.nx {
            n = BlockSize - this.nx
        }

        copy(this.x[this.nx:this.nx+n], p[:n])
        this.nx += n

        if this.nx == BlockSize {
            this.compress(this.x[:BlockSize])
            this.nx = 0
        }

        p = p[n:]
    }

    for len(p) >= BlockSize {
        this.compress(p[:BlockSize])
        p = p[BlockSize:]
    }

    if len(p) > 0 {
        this.nx = copy(this.x[:], p)
    }

    return
}

func (this *digest) Sum(in []byte) []byte {
    // Make a copy of d so that caller can keep writing and summing.
    d0 := *this
    hash := d0.checkSum()
    return append(in, hash[:]...)
}

func (this *digest) checkSum() []byte {
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
        tmp[i] = byte(this.s[0] >> (8 * i))
        tmp[i+8] = byte(this.s[1] >> (8 * i))
        tmp[i+16] = byte(this.s[2] >> (8 * i))
    }

    return tmp[:this.hs]
}

func (this *digest) compress(data []byte) {
    a := this.s[0]
    b := this.s[1]
    c := this.s[2]

    x := bytesToUint64s(data)

    this.s[0], this.s[1], this.s[2] = pass(this.s[0], this.s[1], this.s[2], x, 5)

    keySchedule(x)
    this.s[2], this.s[0], this.s[1] = pass(this.s[2], this.s[0], this.s[1], x, 7)

    keySchedule(x)
    this.s[1], this.s[2], this.s[0] = pass(this.s[1], this.s[2], this.s[0], x, 9)

    this.s[0] ^= a
    this.s[1] -= b
    this.s[2] += c
}
