package hamsi

import (
    "sync"
)

var once256 sync.Once

const (
    // hash size
    Size224 = 28
    Size256 = 32

    // -32
    BlockSize256 = 0
)

// digest256 represents the partial evaluation of a checksum.
type digest256 struct {
    s   [8]uint32
    x   [BlockSize256]byte
    nx  int
    len uint64

    partial    uint32
    partialLen uint32

    initVal [8]uint32
    hs int
}

func initAll256() {
    genTable256()
}

// newDigest256 returns a new *digest256 computing the bmw checksum
func newDigest256(initVal []uint32, hs int) *digest256 {
    d := new(digest256)
    copy(d.initVal[:], initVal)
    d.hs = hs
    d.Reset()

    once256.Do(initAll256)

    return d
}

func (d *digest256) Reset() {
    // h
    d.s = [8]uint32{}
    d.x = [BlockSize256]byte{}

    d.nx = 0
    d.len = 0

    d.partial = 0
    d.partialLen = 0

    copy(d.s[:], d.initVal[:])
}

func (d *digest256) Size() int {
    return d.hs
}

func (d *digest256) BlockSize() int {
    return BlockSize256
}

func (d *digest256) Write(p []byte) (nn int, err error) {
    nn = len(p)

    plen := len(p)
    d.len += uint64(plen) << 3

    off := 0
    if d.partialLen != 0 {
        for d.partialLen < 4 && plen > 0 {
            d.partial = (d.partial << 8) | uint32(p[off] & 0xFF)
            d.partialLen++
            plen--
            off++
        }

        if d.partialLen < 4 {
            return
        }

        d.process(
            d.partial >> 24,
            (d.partial >> 16) & 0xFF,
            (d.partial >> 8) & 0xFF,
            d.partial & 0xFF,
        )
        d.partialLen = 0
    }

    for plen >= 4 {
        d.process(
            uint32(p[off + 0] & 0xFF),
            uint32(p[off + 1] & 0xFF),
            uint32(p[off + 2] & 0xFF),
            uint32(p[off + 3] & 0xFF),
        )

        off += 4
        plen -= 4
    }

    d.partialLen = uint32(plen)
    for plen > 0 {
        d.partial = (d.partial << 8) | uint32(p[off] & 0xFF)
        plen--
        off++
    }

    return
}

func (d *digest256) Sum(in []byte) []byte {
    // Make a copy of d so that caller can keep writing and summing.
    d0 := *d
    hash := d0.checkSum()
    return append(in, hash...)
}

func (d *digest256) checkSum() (out []byte) {
    bitCount := d.len

    d.Write([]byte{0x80})

    for d.partialLen != 0 {
        d.Write([]byte{0x00})
    }

    d.process(
        uint32(bitCount >> 56) & 0xFF,
        uint32(bitCount >> 48) & 0xFF,
        uint32(bitCount >> 40) & 0xFF,
        uint32(bitCount >> 32) & 0xFF,
    )

    d.processFinal(
        uint32(bitCount >> 24) & 0xFF,
        uint32(bitCount >> 16) & 0xFF,
        uint32(bitCount >>  8) & 0xFF,
        uint32(bitCount) & 0xFF,
    )

    len := d.hs
    out = make([]byte, len)

    var ch uint32 = 0
    for i, j := 0, 0; i < len; i++ {
        if (i & 3) == 0 {
            ch = d.s[j]
            j++
        }

        out[i] = byte(ch >> 24)
        ch <<= 8
    }

    return out
}

func (d *digest256) process(b0, b1, b2, b3 uint32) {
    var rp = T256_0[b0]

    var m0 = rp[0]
    var m1 = rp[1]
    var m2 = rp[2]
    var m3 = rp[3]
    var m4 = rp[4]
    var m5 = rp[5]
    var m6 = rp[6]
    var m7 = rp[7]

    rp = T256_1[b1]
    m0 ^= rp[0]
    m1 ^= rp[1]
    m2 ^= rp[2]
    m3 ^= rp[3]
    m4 ^= rp[4]
    m5 ^= rp[5]
    m6 ^= rp[6]
    m7 ^= rp[7]
    rp = T256_2[b2]
    m0 ^= rp[0]
    m1 ^= rp[1]
    m2 ^= rp[2]
    m3 ^= rp[3]
    m4 ^= rp[4]
    m5 ^= rp[5]
    m6 ^= rp[6]
    m7 ^= rp[7]
    rp = T256_3[b3]
    m0 ^= rp[0]
    m1 ^= rp[1]
    m2 ^= rp[2]
    m3 ^= rp[3]
    m4 ^= rp[4]
    m5 ^= rp[5]
    m6 ^= rp[6]
    m7 ^= rp[7]

    var c0 = d.s[0]
    var c1 = d.s[1]
    var c2 = d.s[2]
    var c3 = d.s[3]
    var c4 = d.s[4]
    var c5 = d.s[5]
    var c6 = d.s[6]
    var c7 = d.s[7]
    var t uint32

    m0 ^= ALPHA_N256[0x00]
    m1 ^= ALPHA_N256[0x01] ^ 0
    c0 ^= ALPHA_N256[0x02]
    c1 ^= ALPHA_N256[0x03]
    c2 ^= ALPHA_N256[0x08]
    c3 ^= ALPHA_N256[0x09]
    m2 ^= ALPHA_N256[0x0A]
    m3 ^= ALPHA_N256[0x0B]
    m4 ^= ALPHA_N256[0x10]
    m5 ^= ALPHA_N256[0x11]
    c4 ^= ALPHA_N256[0x12]
    c5 ^= ALPHA_N256[0x13]
    c6 ^= ALPHA_N256[0x18]
    c7 ^= ALPHA_N256[0x19]
    m6 ^= ALPHA_N256[0x1A]
    m7 ^= ALPHA_N256[0x1B]
    t = m0
    m0 &= m4
    m0 ^= c6
    m4 ^= c2
    m4 ^= m0
    c6 |= t
    c6 ^= c2
    t ^= m4
    c2 = c6
    c6 |= t
    c6 ^= m0
    m0 &= c2
    t ^= m0
    c2 ^= c6
    c2 ^= t
    m0 = m4
    m4 = c2
    c2 = c6
    c6 = ^t
    t = m1
    m1 &= m5
    m1 ^= c7
    m5 ^= c3
    m5 ^= m1
    c7 |= t
    c7 ^= c3
    t ^= m5
    c3 = c7
    c7 |= t
    c7 ^= m1
    m1 &= c3
    t ^= m1
    c3 ^= c7
    c3 ^= t
    m1 = m5
    m5 = c3
    c3 = c7
    c7 = ^t
    t = c0
    c0 &= c4
    c0 ^= m6
    c4 ^= m2
    c4 ^= c0
    m6 |= t
    m6 ^= m2
    t ^= c4
    m2 = m6
    m6 |= t
    m6 ^= c0
    c0 &= m2
    t ^= c0
    m2 ^= m6
    m2 ^= t
    c0 = c4
    c4 = m2
    m2 = m6
    m6 = ^t
    t = c1
    c1 &= c5
    c1 ^= m7
    c5 ^= m3
    c5 ^= c1
    m7 |= t
    m7 ^= m3
    t ^= c5
    m3 = m7
    m7 |= t
    m7 ^= c1
    c1 &= m3
    t ^= c1
    m3 ^= m7
    m3 ^= t
    c1 = c5
    c5 = m3
    m3 = m7
    m7 = ^t
    m0 = (m0 << 13) | (m0 >> (32 - 13))
    c4 = (c4 << 3) | (c4 >> (32 - 3))
    c3 ^= m0 ^ c4
    m7 ^= c4 ^ (m0 << 3)
    c3 = (c3 << 1) | (c3 >> (32 - 1))
    m7 = (m7 << 7) | (m7 >> (32 - 7))
    m0 ^= c3 ^ m7
    c4 ^= m7 ^ (c3 << 7)
    m0 = (m0 << 5) | (m0 >> (32 - 5))
    c4 = (c4 << 22) | (c4 >> (32 - 22))
    m1 = (m1 << 13) | (m1 >> (32 - 13))
    c5 = (c5 << 3) | (c5 >> (32 - 3))
    m2 ^= m1 ^ c5
    c6 ^= c5 ^ (m1 << 3)
    m2 = (m2 << 1) | (m2 >> (32 - 1))
    c6 = (c6 << 7) | (c6 >> (32 - 7))
    m1 ^= m2 ^ c6
    c5 ^= c6 ^ (m2 << 7)
    m1 = (m1 << 5) | (m1 >> (32 - 5))
    c5 = (c5 << 22) | (c5 >> (32 - 22))
    c0 = (c0 << 13) | (c0 >> (32 - 13))
    m4 = (m4 << 3) | (m4 >> (32 - 3))
    m3 ^= c0 ^ m4
    c7 ^= m4 ^ (c0 << 3)
    m3 = (m3 << 1) | (m3 >> (32 - 1))
    c7 = (c7 << 7) | (c7 >> (32 - 7))
    c0 ^= m3 ^ c7
    m4 ^= c7 ^ (m3 << 7)
    c0 = (c0 << 5) | (c0 >> (32 - 5))
    m4 = (m4 << 22) | (m4 >> (32 - 22))
    c1 = (c1 << 13) | (c1 >> (32 - 13))
    m5 = (m5 << 3) | (m5 >> (32 - 3))
    c2 ^= c1 ^ m5
    m6 ^= m5 ^ (c1 << 3)
    c2 = (c2 << 1) | (c2 >> (32 - 1))
    m6 = (m6 << 7) | (m6 >> (32 - 7))
    c1 ^= c2 ^ m6
    m5 ^= m6 ^ (c2 << 7)
    c1 = (c1 << 5) | (c1 >> (32 - 5))
    m5 = (m5 << 22) | (m5 >> (32 - 22))
    m0 ^= ALPHA_N256[0x00]
    m1 ^= ALPHA_N256[0x01] ^ 1
    c0 ^= ALPHA_N256[0x02]
    c1 ^= ALPHA_N256[0x03]
    c2 ^= ALPHA_N256[0x08]
    c3 ^= ALPHA_N256[0x09]
    m2 ^= ALPHA_N256[0x0A]
    m3 ^= ALPHA_N256[0x0B]
    m4 ^= ALPHA_N256[0x10]
    m5 ^= ALPHA_N256[0x11]
    c4 ^= ALPHA_N256[0x12]
    c5 ^= ALPHA_N256[0x13]
    c6 ^= ALPHA_N256[0x18]
    c7 ^= ALPHA_N256[0x19]
    m6 ^= ALPHA_N256[0x1A]
    m7 ^= ALPHA_N256[0x1B]
    t = m0
    m0 &= m4
    m0 ^= c6
    m4 ^= c2
    m4 ^= m0
    c6 |= t
    c6 ^= c2
    t ^= m4
    c2 = c6
    c6 |= t
    c6 ^= m0
    m0 &= c2
    t ^= m0
    c2 ^= c6
    c2 ^= t
    m0 = m4
    m4 = c2
    c2 = c6
    c6 = ^t
    t = m1
    m1 &= m5
    m1 ^= c7
    m5 ^= c3
    m5 ^= m1
    c7 |= t
    c7 ^= c3
    t ^= m5
    c3 = c7
    c7 |= t
    c7 ^= m1
    m1 &= c3
    t ^= m1
    c3 ^= c7
    c3 ^= t
    m1 = m5
    m5 = c3
    c3 = c7
    c7 = ^t
    t = c0
    c0 &= c4
    c0 ^= m6
    c4 ^= m2
    c4 ^= c0
    m6 |= t
    m6 ^= m2
    t ^= c4
    m2 = m6
    m6 |= t
    m6 ^= c0
    c0 &= m2
    t ^= c0
    m2 ^= m6
    m2 ^= t
    c0 = c4
    c4 = m2
    m2 = m6
    m6 = ^t
    t = c1
    c1 &= c5
    c1 ^= m7
    c5 ^= m3
    c5 ^= c1
    m7 |= t
    m7 ^= m3
    t ^= c5
    m3 = m7
    m7 |= t
    m7 ^= c1
    c1 &= m3
    t ^= c1
    m3 ^= m7
    m3 ^= t
    c1 = c5
    c5 = m3
    m3 = m7
    m7 = ^t
    m0 = (m0 << 13) | (m0 >> (32 - 13))
    c4 = (c4 << 3) | (c4 >> (32 - 3))
    c3 ^= m0 ^ c4
    m7 ^= c4 ^ (m0 << 3)
    c3 = (c3 << 1) | (c3 >> (32 - 1))
    m7 = (m7 << 7) | (m7 >> (32 - 7))
    m0 ^= c3 ^ m7
    c4 ^= m7 ^ (c3 << 7)
    m0 = (m0 << 5) | (m0 >> (32 - 5))
    c4 = (c4 << 22) | (c4 >> (32 - 22))
    m1 = (m1 << 13) | (m1 >> (32 - 13))
    c5 = (c5 << 3) | (c5 >> (32 - 3))
    m2 ^= m1 ^ c5
    c6 ^= c5 ^ (m1 << 3)
    m2 = (m2 << 1) | (m2 >> (32 - 1))
    c6 = (c6 << 7) | (c6 >> (32 - 7))
    m1 ^= m2 ^ c6
    c5 ^= c6 ^ (m2 << 7)
    m1 = (m1 << 5) | (m1 >> (32 - 5))
    c5 = (c5 << 22) | (c5 >> (32 - 22))
    c0 = (c0 << 13) | (c0 >> (32 - 13))
    m4 = (m4 << 3) | (m4 >> (32 - 3))
    m3 ^= c0 ^ m4
    c7 ^= m4 ^ (c0 << 3)
    m3 = (m3 << 1) | (m3 >> (32 - 1))
    c7 = (c7 << 7) | (c7 >> (32 - 7))
    c0 ^= m3 ^ c7
    m4 ^= c7 ^ (m3 << 7)
    c0 = (c0 << 5) | (c0 >> (32 - 5))
    m4 = (m4 << 22) | (m4 >> (32 - 22))
    c1 = (c1 << 13) | (c1 >> (32 - 13))
    m5 = (m5 << 3) | (m5 >> (32 - 3))
    c2 ^= c1 ^ m5
    m6 ^= m5 ^ (c1 << 3)
    c2 = (c2 << 1) | (c2 >> (32 - 1))
    m6 = (m6 << 7) | (m6 >> (32 - 7))
    c1 ^= c2 ^ m6
    m5 ^= m6 ^ (c2 << 7)
    c1 = (c1 << 5) | (c1 >> (32 - 5))
    m5 = (m5 << 22) | (m5 >> (32 - 22))
    m0 ^= ALPHA_N256[0x00]
    m1 ^= ALPHA_N256[0x01] ^ 2
    c0 ^= ALPHA_N256[0x02]
    c1 ^= ALPHA_N256[0x03]
    c2 ^= ALPHA_N256[0x08]
    c3 ^= ALPHA_N256[0x09]
    m2 ^= ALPHA_N256[0x0A]
    m3 ^= ALPHA_N256[0x0B]
    m4 ^= ALPHA_N256[0x10]
    m5 ^= ALPHA_N256[0x11]
    c4 ^= ALPHA_N256[0x12]
    c5 ^= ALPHA_N256[0x13]
    c6 ^= ALPHA_N256[0x18]
    c7 ^= ALPHA_N256[0x19]
    m6 ^= ALPHA_N256[0x1A]
    m7 ^= ALPHA_N256[0x1B]
    t = m0
    m0 &= m4
    m0 ^= c6
    m4 ^= c2
    m4 ^= m0
    c6 |= t
    c6 ^= c2
    t ^= m4
    c2 = c6
    c6 |= t
    c6 ^= m0
    m0 &= c2
    t ^= m0
    c2 ^= c6
    c2 ^= t
    m0 = m4
    m4 = c2
    c2 = c6
    c6 = ^t
    t = m1
    m1 &= m5
    m1 ^= c7
    m5 ^= c3
    m5 ^= m1
    c7 |= t
    c7 ^= c3
    t ^= m5
    c3 = c7
    c7 |= t
    c7 ^= m1
    m1 &= c3
    t ^= m1
    c3 ^= c7
    c3 ^= t
    m1 = m5
    m5 = c3
    c3 = c7
    c7 = ^t
    t = c0
    c0 &= c4
    c0 ^= m6
    c4 ^= m2
    c4 ^= c0
    m6 |= t
    m6 ^= m2
    t ^= c4
    m2 = m6
    m6 |= t
    m6 ^= c0
    c0 &= m2
    t ^= c0
    m2 ^= m6
    m2 ^= t
    c0 = c4
    c4 = m2
    m2 = m6
    m6 = ^t
    t = c1
    c1 &= c5
    c1 ^= m7
    c5 ^= m3
    c5 ^= c1
    m7 |= t
    m7 ^= m3
    t ^= c5
    m3 = m7
    m7 |= t
    m7 ^= c1
    c1 &= m3
    t ^= c1
    m3 ^= m7
    m3 ^= t
    c1 = c5
    c5 = m3
    m3 = m7
    m7 = ^t
    m0 = (m0 << 13) | (m0 >> (32 - 13))
    c4 = (c4 << 3) | (c4 >> (32 - 3))
    c3 ^= m0 ^ c4
    m7 ^= c4 ^ (m0 << 3)
    c3 = (c3 << 1) | (c3 >> (32 - 1))
    m7 = (m7 << 7) | (m7 >> (32 - 7))
    m0 ^= c3 ^ m7
    c4 ^= m7 ^ (c3 << 7)
    m0 = (m0 << 5) | (m0 >> (32 - 5))
    c4 = (c4 << 22) | (c4 >> (32 - 22))
    m1 = (m1 << 13) | (m1 >> (32 - 13))
    c5 = (c5 << 3) | (c5 >> (32 - 3))
    m2 ^= m1 ^ c5
    c6 ^= c5 ^ (m1 << 3)
    m2 = (m2 << 1) | (m2 >> (32 - 1))
    c6 = (c6 << 7) | (c6 >> (32 - 7))
    m1 ^= m2 ^ c6
    c5 ^= c6 ^ (m2 << 7)
    m1 = (m1 << 5) | (m1 >> (32 - 5))
    c5 = (c5 << 22) | (c5 >> (32 - 22))
    c0 = (c0 << 13) | (c0 >> (32 - 13))
    m4 = (m4 << 3) | (m4 >> (32 - 3))
    m3 ^= c0 ^ m4
    c7 ^= m4 ^ (c0 << 3)
    m3 = (m3 << 1) | (m3 >> (32 - 1))
    c7 = (c7 << 7) | (c7 >> (32 - 7))
    c0 ^= m3 ^ c7
    m4 ^= c7 ^ (m3 << 7)
    c0 = (c0 << 5) | (c0 >> (32 - 5))
    m4 = (m4 << 22) | (m4 >> (32 - 22))
    c1 = (c1 << 13) | (c1 >> (32 - 13))
    m5 = (m5 << 3) | (m5 >> (32 - 3))
    c2 ^= c1 ^ m5
    m6 ^= m5 ^ (c1 << 3)
    c2 = (c2 << 1) | (c2 >> (32 - 1))
    m6 = (m6 << 7) | (m6 >> (32 - 7))
    c1 ^= c2 ^ m6
    m5 ^= m6 ^ (c2 << 7)
    c1 = (c1 << 5) | (c1 >> (32 - 5))
    m5 = (m5 << 22) | (m5 >> (32 - 22))

    d.s[7] ^= c5
    d.s[6] ^= c4
    d.s[5] ^= m5
    d.s[4] ^= m4
    d.s[3] ^= c1
    d.s[2] ^= c0
    d.s[1] ^= m1
    d.s[0] ^= m0
}

func (d *digest256) processFinal(b0, b1, b2, b3 uint32) {
    var rp = T256_0[b0]

    var m0 = rp[0]
    var m1 = rp[1]
    var m2 = rp[2]
    var m3 = rp[3]
    var m4 = rp[4]
    var m5 = rp[5]
    var m6 = rp[6]
    var m7 = rp[7]

    rp = T256_1[b1]
    m0 ^= rp[0]
    m1 ^= rp[1]
    m2 ^= rp[2]
    m3 ^= rp[3]
    m4 ^= rp[4]
    m5 ^= rp[5]
    m6 ^= rp[6]
    m7 ^= rp[7]
    rp = T256_2[b2]
    m0 ^= rp[0]
    m1 ^= rp[1]
    m2 ^= rp[2]
    m3 ^= rp[3]
    m4 ^= rp[4]
    m5 ^= rp[5]
    m6 ^= rp[6]
    m7 ^= rp[7]
    rp = T256_3[b3]
    m0 ^= rp[0]
    m1 ^= rp[1]
    m2 ^= rp[2]
    m3 ^= rp[3]
    m4 ^= rp[4]
    m5 ^= rp[5]
    m6 ^= rp[6]
    m7 ^= rp[7]

    var c0 = d.s[0]
    var c1 = d.s[1]
    var c2 = d.s[2]
    var c3 = d.s[3]
    var c4 = d.s[4]
    var c5 = d.s[5]
    var c6 = d.s[6]
    var c7 = d.s[7]
    var t uint32

    for r := 0; r < 6; r++ {
        m0 ^= ALPHA_F256[0x00]
        m1 ^= ALPHA_F256[0x01] ^ uint32(r)
        c0 ^= ALPHA_F256[0x02]
        c1 ^= ALPHA_F256[0x03]
        c2 ^= ALPHA_F256[0x08]
        c3 ^= ALPHA_F256[0x09]
        m2 ^= ALPHA_F256[0x0A]
        m3 ^= ALPHA_F256[0x0B]
        m4 ^= ALPHA_F256[0x10]
        m5 ^= ALPHA_F256[0x11]
        c4 ^= ALPHA_F256[0x12]
        c5 ^= ALPHA_F256[0x13]
        c6 ^= ALPHA_F256[0x18]
        c7 ^= ALPHA_F256[0x19]
        m6 ^= ALPHA_F256[0x1A]
        m7 ^= ALPHA_F256[0x1B]
        t = m0
        m0 &= m4
        m0 ^= c6
        m4 ^= c2
        m4 ^= m0
        c6 |= t
        c6 ^= c2
        t ^= m4
        c2 = c6
        c6 |= t
        c6 ^= m0
        m0 &= c2
        t ^= m0
        c2 ^= c6
        c2 ^= t
        m0 = m4
        m4 = c2
        c2 = c6
        c6 = ^t
        t = m1
        m1 &= m5
        m1 ^= c7
        m5 ^= c3
        m5 ^= m1
        c7 |= t
        c7 ^= c3
        t ^= m5
        c3 = c7
        c7 |= t
        c7 ^= m1
        m1 &= c3
        t ^= m1
        c3 ^= c7
        c3 ^= t
        m1 = m5
        m5 = c3
        c3 = c7
        c7 = ^t
        t = c0
        c0 &= c4
        c0 ^= m6
        c4 ^= m2
        c4 ^= c0
        m6 |= t
        m6 ^= m2
        t ^= c4
        m2 = m6
        m6 |= t
        m6 ^= c0
        c0 &= m2
        t ^= c0
        m2 ^= m6
        m2 ^= t
        c0 = c4
        c4 = m2
        m2 = m6
        m6 = ^t
        t = c1
        c1 &= c5
        c1 ^= m7
        c5 ^= m3
        c5 ^= c1
        m7 |= t
        m7 ^= m3
        t ^= c5
        m3 = m7
        m7 |= t
        m7 ^= c1
        c1 &= m3
        t ^= c1
        m3 ^= m7
        m3 ^= t
        c1 = c5
        c5 = m3
        m3 = m7
        m7 = ^t
        m0 = (m0 << 13) | (m0 >> (32 - 13))
        c4 = (c4 << 3) | (c4 >> (32 - 3))
        c3 ^= m0 ^ c4
        m7 ^= c4 ^ (m0 << 3)
        c3 = (c3 << 1) | (c3 >> (32 - 1))
        m7 = (m7 << 7) | (m7 >> (32 - 7))
        m0 ^= c3 ^ m7
        c4 ^= m7 ^ (c3 << 7)
        m0 = (m0 << 5) | (m0 >> (32 - 5))
        c4 = (c4 << 22) | (c4 >> (32 - 22))
        m1 = (m1 << 13) | (m1 >> (32 - 13))
        c5 = (c5 << 3) | (c5 >> (32 - 3))
        m2 ^= m1 ^ c5
        c6 ^= c5 ^ (m1 << 3)
        m2 = (m2 << 1) | (m2 >> (32 - 1))
        c6 = (c6 << 7) | (c6 >> (32 - 7))
        m1 ^= m2 ^ c6
        c5 ^= c6 ^ (m2 << 7)
        m1 = (m1 << 5) | (m1 >> (32 - 5))
        c5 = (c5 << 22) | (c5 >> (32 - 22))
        c0 = (c0 << 13) | (c0 >> (32 - 13))
        m4 = (m4 << 3) | (m4 >> (32 - 3))
        m3 ^= c0 ^ m4
        c7 ^= m4 ^ (c0 << 3)
        m3 = (m3 << 1) | (m3 >> (32 - 1))
        c7 = (c7 << 7) | (c7 >> (32 - 7))
        c0 ^= m3 ^ c7
        m4 ^= c7 ^ (m3 << 7)
        c0 = (c0 << 5) | (c0 >> (32 - 5))
        m4 = (m4 << 22) | (m4 >> (32 - 22))
        c1 = (c1 << 13) | (c1 >> (32 - 13))
        m5 = (m5 << 3) | (m5 >> (32 - 3))
        c2 ^= c1 ^ m5
        m6 ^= m5 ^ (c1 << 3)
        c2 = (c2 << 1) | (c2 >> (32 - 1))
        m6 = (m6 << 7) | (m6 >> (32 - 7))
        c1 ^= c2 ^ m6
        m5 ^= m6 ^ (c2 << 7)
        c1 = (c1 << 5) | (c1 >> (32 - 5))
        m5 = (m5 << 22) | (m5 >> (32 - 22))
    }

    d.s[7] ^= c5
    d.s[6] ^= c4
    d.s[5] ^= m5
    d.s[4] ^= m4
    d.s[3] ^= c1
    d.s[2] ^= c0
    d.s[1] ^= m1
    d.s[0] ^= m0
}
