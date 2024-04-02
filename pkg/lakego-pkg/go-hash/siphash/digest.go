package siphash

import (
    "hash"
    "errors"
)

// The blocksize of Siphash in bytes.
const BlockSize = 8

const KeySize   = 16

const HashSize64  = 8
const HashSize128 = 16

const MinDigestSize = 8
const MaxDigestSize = 16

const CRounds = 2
const DRounds = 4

type digest struct {
    s   [4]uint64
    x   [BlockSize]byte
    nx  int
    len uint64

    hs uint32
    crounds uint32
    drounds uint32
}

// newDigest returns a new hash.Hash computing the Siphash checksum.
func newDigest(k []byte, crounds, drounds int32, hashSize int) (hash.Hash, error) {
    if len(k) != KeySize {
        return nil, errors.New("go-hash/siphash: invalid key")
    }

    h := new(digest)
    h.setHashSize(hashSize)
    h.expandKey(k, crounds, drounds)

    return h, nil
}

func (this *digest) Size() int {
    return int(this.hs)
}

func (this *digest) BlockSize() int {
    return BlockSize
}

func (this *digest) Reset() {
    this.x = [BlockSize]byte{}

    this.nx = 0
    this.len = 0
}

func (this *digest) Write(p []byte) (nn int, err error) {
    nn = len(p)

    plen := len(p)

    var limit = BlockSize
    for this.nx + plen >= limit {
        xx := limit - this.nx

        copy(this.x[this.nx:], p)

        this.transform(this.x[:])

        plen -= xx
        this.len += uint64(xx)

        p = p[xx:]
        this.nx = 0
    }

    copy(this.x[this.nx:], p)
    this.nx += plen
    this.len += uint64(plen)

    return
}

func (this *digest) Sum(p []byte) []byte {
    // Make a copy of d so that caller can keep writing and summing.
    d0 := *this
    hash := d0.checkSum()
    return append(p, hash[:]...)
}

func (this *digest) checkSum() (hash []byte) {
    if this.crounds == 0 {
        return nil
    }

    b := this.len << 56
    switch this.nx {
        case 7:
            b |= uint64(this.x[6]) << 48
            fallthrough
        case 6:
            b |= uint64(this.x[5]) << 40
            fallthrough
        case 5:
            b |= uint64(this.x[4]) << 32
            fallthrough
        case 4:
            b |= uint64(this.x[3]) << 24
            fallthrough
        case 3:
            b |= uint64(this.x[2]) << 16
            fallthrough
        case 2:
            b |= uint64(this.x[1]) <<  8
            fallthrough
        case 1:
            b |= uint64(this.x[0])
            fallthrough
        case 0:
            break
    }

    var bb [8]byte
    PUTU64(bb[:], b)

    this.transform(bb[:])

    if (this.hs == MaxDigestSize) {
        this.s[2] ^= 0xee
    } else {
        this.s[2] ^= 0xff
    }

    out := make([]byte, this.hs)

    var i uint32
    for i = 0; i < this.drounds; i++ {
        sipround(&this.s[0], &this.s[1], &this.s[2], &this.s[3])
    }

    b = this.s[0] ^ this.s[1] ^ this.s[2]  ^ this.s[3]
    PUTU64(out, b)

    if (this.hs == MinDigestSize) {
        return out
    }

    this.s[1] ^= 0xdd
    for i = 0; i < this.drounds; i++ {
        sipround(&this.s[0], &this.s[1], &this.s[2], &this.s[3])
    }

    b = this.s[0] ^ this.s[1] ^ this.s[2]  ^ this.s[3]
    PUTU64(out[8:], b)

    return out
}

func (this *digest) setHashSize(hashSize int) bool {
    hashSize = this.adjustHashSize(hashSize)

    if (hashSize != MinDigestSize && hashSize != MaxDigestSize) {
        return false
    }

    this.hs = uint32(this.adjustHashSize(int(this.hs)))

    if (int(this.hs) != hashSize) {
        this.s[1] ^= 0xee
        this.hs = uint32(hashSize)
    }

    return true
}

func (this *digest) adjustHashSize(hashSize int) int {
    if (hashSize == 0) {
        hashSize = MaxDigestSize
    }

    return hashSize
}

func (this *digest) expandKey(k []byte, crounds, drounds int32) {
    k0 := GETU64(k)
    k1 := GETU64(k[8:])

    this.hs = uint32(this.adjustHashSize(int(this.hs)))

    if (drounds == 0) {
        drounds = DRounds
    }
    if (crounds == 0) {
        crounds = CRounds
    }

    this.crounds = uint32(crounds)
    this.drounds = uint32(drounds)

    this.nx = 0
    this.len = 0

    this.s[0] = 0x736f6d6570736575 ^ k0
    this.s[1] = 0x646f72616e646f6d ^ k1
    this.s[2] = 0x6c7967656e657261 ^ k0
    this.s[3] = 0x7465646279746573 ^ k1

    if (this.hs == MaxDigestSize) {
        this.s[1] ^= 0xee
    }
}

func (this *digest) transform(x []byte) {
    m := GETU64(x)
    this.s[3] ^= m

    var i uint32
    for i = 0; i < this.crounds; i++ {
        sipround(&this.s[0], &this.s[1], &this.s[2], &this.s[3])
    }

    this.s[0] ^= m
}
