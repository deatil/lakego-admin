package siphash

import (
    "hash"
    "bytes"
)

// The blocksize of Siphash in bytes.
const BlockSize = 8

const HashSize64  = 8
const HashSize128 = 16

// New returns a new hash.Hash computing the Siphash checksum.
func New(k []byte) hash.Hash {
    return NewWithCDroundsAndHashSize(k, 0, 0, 0)
}

// return 8 bytes
func New64(k []byte) hash.Hash {
    return NewWithCDroundsAndHashSize(k, 0, 0, HashSize64)
}

// New alias, return 16 bytes
func New128(k []byte) hash.Hash {
    return NewWithCDroundsAndHashSize(k, 0, 0, HashSize128)
}

// NewWithHashSize returns a new hash.Hash computing the Siphash checksum.
func NewWithHashSize(k []byte, hashSize int) hash.Hash {
    return NewWithCDroundsAndHashSize(k, 0, 0, hashSize)
}

// NewWithCDroundsAndHashSize returns a new hash.Hash computing the Siphash checksum.
func NewWithCDroundsAndHashSize(k []byte, crounds, drounds int32, hashSize int) hash.Hash {
    if len(k) != KEY_SIZE {
        panic("siphash: invalid key")
    }

    h := new(digest)
    h.setHashSize(hashSize)
    h.init(k, crounds, drounds)

    return h
}

type digest struct {
    totalInlen uint64
    v0 uint64
    v1 uint64
    v2 uint64
    v3 uint64

    len uint32
    hashSize uint32
    crounds uint32
    drounds uint32
    leavings [BLOCK_SIZE]byte
}

func (this *digest) Size() int {
    return int(this.hashSize)
}

func (this *digest) BlockSize() int {
    return BlockSize
}

func (this *digest) Reset() {
    this.len = 0
    this.totalInlen = 0

    this.leavings = [BLOCK_SIZE]byte{}
}

func (this *digest) Write(p []byte) (n int, err error) {
    var m uint64
    var end []byte
    var left int32
    var i uint32
    var v0 uint64 = this.v0
    var v1 uint64 = this.v1
    var v2 uint64 = this.v2
    var v3 uint64 = this.v3

    var inlen int = len(p)

    var in []byte = make([]byte, inlen)
    copy(in, p)

    n = inlen

    this.totalInlen += uint64(inlen)

    if this.len > 0 {
        /* deal with leavings */
        var available int = BLOCK_SIZE - int(this.len)

        /* not enough to fill leavings */
        if (inlen < available) {
            copy(this.leavings[this.len:], in)
            this.len += uint32(inlen)
            return
        }

        /* copy data into leavings and reduce input */
        copy(this.leavings[this.len:], in[:available])
        inlen -= available
        in = in[available:]

        /* process leavings */
        m = U8TO64_LE(this.leavings[:])
        v3 ^= m

        for i = 0; i < this.crounds; i++ {
            SIPROUND(&v0, &v1, &v2, &v3)
        }

        v0 ^= m
    }

    left = int32(inlen & (BLOCK_SIZE-1)) /* gets put into leavings */
    end = in[inlen - int(left):]

    for !bytes.Equal(in, end) {
        m = U8TO64_LE(in)
        v3 ^= m
        for i = 0; i < this.crounds; i++ {
            SIPROUND(&v0, &v1, &v2, &v3)
        }
        v0 ^= m

        in = in[8:]
    }

    /* save leavings and other ctx */
    if left > 0 {
        copy(this.leavings[:], end[:])
    }
    this.len = uint32(left)

    this.v0 = v0
    this.v1 = v1
    this.v2 = v2
    this.v3 = v3

    return
}

func (this *digest) Sum(p []byte) []byte {
    hash := this.checkSum()
    return append(p, hash[:]...)
}

func (this *digest) checkSum() (hash []byte) {
    var i uint32
    var b uint64 = this.totalInlen << 56
    var v0 uint64 = this.v0
    var v1 uint64 = this.v1
    var v2 uint64 = this.v2
    var v3 uint64 = this.v3

    var out []byte = make([]byte, this.hashSize)

    if this.crounds == 0 {
        return nil
    }

    switch this.len {
        case 7:
            b |= uint64(this.leavings[6]) << 48
            fallthrough
        case 6:
            b |= uint64(this.leavings[5]) << 40
            fallthrough
        case 5:
            b |= uint64(this.leavings[4]) << 32
            fallthrough
        case 4:
            b |= uint64(this.leavings[3]) << 24
            fallthrough
        case 3:
            b |= uint64(this.leavings[2]) << 16
            fallthrough
        case 2:
            b |= uint64(this.leavings[1]) <<  8
            fallthrough
        case 1:
            b |= uint64(this.leavings[0])
            fallthrough
        case 0:
            break
    }

    v3 ^= b
    for i = 0; i < this.crounds; i++ {
        SIPROUND(&v0, &v1, &v2, &v3)
    }

    v0 ^= b

    if (this.hashSize == MAX_DIGEST_SIZE) {
        v2 ^= 0xee
    } else {
        v2 ^= 0xff
    }

    for i = 0; i < this.drounds; i++ {
        SIPROUND(&v0, &v1, &v2, &v3)
    }

    b = v0 ^ v1 ^ v2  ^ v3

    U64TO8_LE(out, b)

    if (this.hashSize == MIN_DIGEST_SIZE) {
        return out
    }

    v1 ^= 0xdd

    for i = 0; i < this.drounds; i++ {
        SIPROUND(&v0, &v1, &v2, &v3)
    }

    b = v0 ^ v1 ^ v2  ^ v3
    U64TO8_LE(out[8:], b)

    return out
}

func (this *digest) setHashSize(hashSize int) bool {
    hashSize = this.adjustHashSize(hashSize)

    if (hashSize != MIN_DIGEST_SIZE && hashSize != MAX_DIGEST_SIZE) {
        return false
    }

    this.hashSize = uint32(this.adjustHashSize(int(this.hashSize)))

    if (int(this.hashSize) != hashSize) {
        this.v1 ^= 0xee
        this.hashSize = uint32(hashSize)
    }

    return true
}

func (this *digest) adjustHashSize(hashSize int) int {
    if (hashSize == 0) {
        hashSize = MAX_DIGEST_SIZE
    }

    return hashSize
}

func (this *digest) init(k []byte, crounds, drounds int32) {
    var k0 uint64 = U8TO64_LE(k)
    var k1 uint64 = U8TO64_LE(k[8:])

    this.hashSize = uint32(this.adjustHashSize(int(this.hashSize)))

    if (drounds == 0) {
        drounds = D_ROUNDS
    }
    if (crounds == 0) {
        crounds = C_ROUNDS
    }

    this.crounds = uint32(crounds)
    this.drounds = uint32(drounds)

    this.len = 0
    this.totalInlen = 0

    this.v0 = 0x736f6d6570736575 ^ k0
    this.v1 = 0x646f72616e646f6d ^ k1
    this.v2 = 0x6c7967656e657261 ^ k0
    this.v3 = 0x7465646279746573 ^ k1

    if (this.hashSize == MAX_DIGEST_SIZE) {
        this.v1 ^= 0xee
    }
}
