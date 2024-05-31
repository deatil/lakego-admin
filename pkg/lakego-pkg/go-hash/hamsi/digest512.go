package hamsi

import (
    "sync"
)

var once512 sync.Once

const (
    // hash size
    Size384 = 48
    Size512 = 64

    BlockSize512 = 32
)

// digest512 represents the partial evaluation of a checksum.
type digest512 struct {
    s   [16]uint32
    x   [BlockSize512]byte
    nx  int
    len uint64

    partial    uint64
    partialLen uint32

    initVal [16]uint32
    hs      int
}

func initAll512() {
    genTable512()
}

// newDigest512 returns a new *digest512 computing the bmw checksum
func newDigest512(initVal []uint32, hs int) *digest512 {
    d := new(digest512)
    copy(d.initVal[:], initVal)
    d.hs = hs
    d.Reset()

    once512.Do(initAll512)

    return d
}

func (d *digest512) Reset() {
    // h
    d.s = [16]uint32{}
    d.x = [BlockSize512]byte{}

    d.nx = 0
    d.len = 0

    d.partial = 0
    d.partialLen = 0

    copy(d.s[:], d.initVal[:])
}

func (d *digest512) Size() int {
    return d.hs
}

func (d *digest512) BlockSize() int {
    return BlockSize512
}

func (d *digest512) Write(p []byte) (nn int, err error) {
    nn = len(p)

    plen := len(p)
    d.len += uint64(plen) << 3

    off := 0
    if d.partialLen != 0 {
        for d.partialLen < 8 && plen > 0 {
            d.partial = (d.partial << 8) | uint64(p[off] & 0xFF)
            d.partialLen++
            plen--
            off++
        }

        if d.partialLen < 8 {
            return
        }

        d.process(
            uint32(d.partial >> 56) & 0xFF,
            uint32(d.partial >> 48) & 0xFF,
            uint32(d.partial >> 40) & 0xFF,
            uint32(d.partial >> 32) & 0xFF,
            uint32(d.partial >> 24) & 0xFF,
            uint32(d.partial >> 16) & 0xFF,
            uint32(d.partial >> 8) & 0xFF,
            uint32(d.partial) & 0xFF,
        )
        d.partialLen = 0
    }

    for plen >= 8 {
        d.process(
            uint32(p[off + 0] & 0xFF),
            uint32(p[off + 1] & 0xFF),
            uint32(p[off + 2] & 0xFF),
            uint32(p[off + 3] & 0xFF),
            uint32(p[off + 4] & 0xFF),
            uint32(p[off + 5] & 0xFF),
            uint32(p[off + 6] & 0xFF),
            uint32(p[off + 7] & 0xFF),
        )

        off += 8
        plen -= 8
    }

    d.partialLen = uint32(plen)
    for plen > 0 {
        d.partial = (d.partial << 8) | uint64(p[off] & 0xFF)
        plen--
        off++
    }

    return
}

func (d *digest512) Sum(in []byte) []byte {
    // Make a copy of d so that caller can keep writing and summing.
    d0 := *d
    hash := d0.checkSum()
    return append(in, hash...)
}

func (d *digest512) checkSum() (out []byte) {
    bitCount := d.len

    d.Write([]byte{0x80})

    for d.partialLen != 0 {
        d.Write([]byte{0x00})
    }

    d.processFinal(
        uint32(bitCount >> 56) & 0xFF,
        uint32(bitCount >> 48) & 0xFF,
        uint32(bitCount >> 40) & 0xFF,
        uint32(bitCount >> 32) & 0xFF,
        uint32(bitCount >> 24) & 0xFF,
        uint32(bitCount >> 16) & 0xFF,
        uint32(bitCount >>  8) & 0xFF,
        uint32(bitCount) & 0xFF,
    )

    len := d.hs
    out = make([]byte, len)

    var ch uint32 = 0
    var hoff []uint32

    if d.hs == 48 {
        hoff = HOFF384
    } else {
        hoff = HOFF512
    }

    for i, j := 0, 0; i < len; i++ {
        if (i & 3) == 0 {
            ch = d.s[hoff[j]]
            j++
        }

        out[i] = byte(ch >> 24)
        ch <<= 8
    }

    return out
}

func (d *digest512) process(
    b0, b1, b2, b3 uint32,
    b4, b5, b6, b7 uint32,
) {
    var rp = T512_0[b0]
    var m0 = rp[0x0]
    var m1 = rp[0x1]
    var m2 = rp[0x2]
    var m3 = rp[0x3]
    var m4 = rp[0x4]
    var m5 = rp[0x5]
    var m6 = rp[0x6]
    var m7 = rp[0x7]
    var m8 = rp[0x8]
    var m9 = rp[0x9]
    var mA = rp[0xA]
    var mB = rp[0xB]
    var mC = rp[0xC]
    var mD = rp[0xD]
    var mE = rp[0xE]
    var mF = rp[0xF]

    rp = T512_1[b1]
    m0 ^= rp[0x0]
    m1 ^= rp[0x1]
    m2 ^= rp[0x2]
    m3 ^= rp[0x3]
    m4 ^= rp[0x4]
    m5 ^= rp[0x5]
    m6 ^= rp[0x6]
    m7 ^= rp[0x7]
    m8 ^= rp[0x8]
    m9 ^= rp[0x9]
    mA ^= rp[0xA]
    mB ^= rp[0xB]
    mC ^= rp[0xC]
    mD ^= rp[0xD]
    mE ^= rp[0xE]
    mF ^= rp[0xF]
    rp = T512_2[b2]
    m0 ^= rp[0x0]
    m1 ^= rp[0x1]
    m2 ^= rp[0x2]
    m3 ^= rp[0x3]
    m4 ^= rp[0x4]
    m5 ^= rp[0x5]
    m6 ^= rp[0x6]
    m7 ^= rp[0x7]
    m8 ^= rp[0x8]
    m9 ^= rp[0x9]
    mA ^= rp[0xA]
    mB ^= rp[0xB]
    mC ^= rp[0xC]
    mD ^= rp[0xD]
    mE ^= rp[0xE]
    mF ^= rp[0xF]
    rp = T512_3[b3]
    m0 ^= rp[0x0]
    m1 ^= rp[0x1]
    m2 ^= rp[0x2]
    m3 ^= rp[0x3]
    m4 ^= rp[0x4]
    m5 ^= rp[0x5]
    m6 ^= rp[0x6]
    m7 ^= rp[0x7]
    m8 ^= rp[0x8]
    m9 ^= rp[0x9]
    mA ^= rp[0xA]
    mB ^= rp[0xB]
    mC ^= rp[0xC]
    mD ^= rp[0xD]
    mE ^= rp[0xE]
    mF ^= rp[0xF]
    rp = T512_4[b4]
    m0 ^= rp[0x0]
    m1 ^= rp[0x1]
    m2 ^= rp[0x2]
    m3 ^= rp[0x3]
    m4 ^= rp[0x4]
    m5 ^= rp[0x5]
    m6 ^= rp[0x6]
    m7 ^= rp[0x7]
    m8 ^= rp[0x8]
    m9 ^= rp[0x9]
    mA ^= rp[0xA]
    mB ^= rp[0xB]
    mC ^= rp[0xC]
    mD ^= rp[0xD]
    mE ^= rp[0xE]
    mF ^= rp[0xF]
    rp = T512_5[b5]
    m0 ^= rp[0x0]
    m1 ^= rp[0x1]
    m2 ^= rp[0x2]
    m3 ^= rp[0x3]
    m4 ^= rp[0x4]
    m5 ^= rp[0x5]
    m6 ^= rp[0x6]
    m7 ^= rp[0x7]
    m8 ^= rp[0x8]
    m9 ^= rp[0x9]
    mA ^= rp[0xA]
    mB ^= rp[0xB]
    mC ^= rp[0xC]
    mD ^= rp[0xD]
    mE ^= rp[0xE]
    mF ^= rp[0xF]
    rp = T512_6[b6]
    m0 ^= rp[0x0]
    m1 ^= rp[0x1]
    m2 ^= rp[0x2]
    m3 ^= rp[0x3]
    m4 ^= rp[0x4]
    m5 ^= rp[0x5]
    m6 ^= rp[0x6]
    m7 ^= rp[0x7]
    m8 ^= rp[0x8]
    m9 ^= rp[0x9]
    mA ^= rp[0xA]
    mB ^= rp[0xB]
    mC ^= rp[0xC]
    mD ^= rp[0xD]
    mE ^= rp[0xE]
    mF ^= rp[0xF]
    rp = T512_7[b7]
    m0 ^= rp[0x0]
    m1 ^= rp[0x1]
    m2 ^= rp[0x2]
    m3 ^= rp[0x3]
    m4 ^= rp[0x4]
    m5 ^= rp[0x5]
    m6 ^= rp[0x6]
    m7 ^= rp[0x7]
    m8 ^= rp[0x8]
    m9 ^= rp[0x9]
    mA ^= rp[0xA]
    mB ^= rp[0xB]
    mC ^= rp[0xC]
    mD ^= rp[0xD]
    mE ^= rp[0xE]
    mF ^= rp[0xF]

    var c0 = d.s[0x0]
    var c1 = d.s[0x1]
    var c2 = d.s[0x2]
    var c3 = d.s[0x3]
    var c4 = d.s[0x4]
    var c5 = d.s[0x5]
    var c6 = d.s[0x6]
    var c7 = d.s[0x7]
    var c8 = d.s[0x8]
    var c9 = d.s[0x9]
    var cA = d.s[0xA]
    var cB = d.s[0xB]
    var cC = d.s[0xC]
    var cD = d.s[0xD]
    var cE = d.s[0xE]
    var cF = d.s[0xF]
    var t uint32

    for r := 0; r < 6; r++ {
        m0 ^= ALPHA_N512[0x00]
        m1 ^= ALPHA_N512[0x01] ^ uint32(r)
        c0 ^= ALPHA_N512[0x02]
        c1 ^= ALPHA_N512[0x03]
        m2 ^= ALPHA_N512[0x04]
        m3 ^= ALPHA_N512[0x05]
        c2 ^= ALPHA_N512[0x06]
        c3 ^= ALPHA_N512[0x07]
        c4 ^= ALPHA_N512[0x08]
        c5 ^= ALPHA_N512[0x09]
        m4 ^= ALPHA_N512[0x0A]
        m5 ^= ALPHA_N512[0x0B]
        c6 ^= ALPHA_N512[0x0C]
        c7 ^= ALPHA_N512[0x0D]
        m6 ^= ALPHA_N512[0x0E]
        m7 ^= ALPHA_N512[0x0F]
        m8 ^= ALPHA_N512[0x10]
        m9 ^= ALPHA_N512[0x11]
        c8 ^= ALPHA_N512[0x12]
        c9 ^= ALPHA_N512[0x13]
        mA ^= ALPHA_N512[0x14]
        mB ^= ALPHA_N512[0x15]
        cA ^= ALPHA_N512[0x16]
        cB ^= ALPHA_N512[0x17]
        cC ^= ALPHA_N512[0x18]
        cD ^= ALPHA_N512[0x19]
        mC ^= ALPHA_N512[0x1A]
        mD ^= ALPHA_N512[0x1B]
        cE ^= ALPHA_N512[0x1C]
        cF ^= ALPHA_N512[0x1D]
        mE ^= ALPHA_N512[0x1E]
        mF ^= ALPHA_N512[0x1F]
        t = m0
        m0 &= m8
        m0 ^= cC
        m8 ^= c4
        m8 ^= m0
        cC |= t
        cC ^= c4
        t ^= m8
        c4 = cC
        cC |= t
        cC ^= m0
        m0 &= c4
        t ^= m0
        c4 ^= cC
        c4 ^= t
        m0 = m8
        m8 = c4
        c4 = cC
        cC = ^t
        t = m1
        m1 &= m9
        m1 ^= cD
        m9 ^= c5
        m9 ^= m1
        cD |= t
        cD ^= c5
        t ^= m9
        c5 = cD
        cD |= t
        cD ^= m1
        m1 &= c5
        t ^= m1
        c5 ^= cD
        c5 ^= t
        m1 = m9
        m9 = c5
        c5 = cD
        cD = ^t
        t = c0
        c0 &= c8
        c0 ^= mC
        c8 ^= m4
        c8 ^= c0
        mC |= t
        mC ^= m4
        t ^= c8
        m4 = mC
        mC |= t
        mC ^= c0
        c0 &= m4
        t ^= c0
        m4 ^= mC
        m4 ^= t
        c0 = c8
        c8 = m4
        m4 = mC
        mC = ^t
        t = c1
        c1 &= c9
        c1 ^= mD
        c9 ^= m5
        c9 ^= c1
        mD |= t
        mD ^= m5
        t ^= c9
        m5 = mD
        mD |= t
        mD ^= c1
        c1 &= m5
        t ^= c1
        m5 ^= mD
        m5 ^= t
        c1 = c9
        c9 = m5
        m5 = mD
        mD = ^t
        t = m2
        m2 &= mA
        m2 ^= cE
        mA ^= c6
        mA ^= m2
        cE |= t
        cE ^= c6
        t ^= mA
        c6 = cE
        cE |= t
        cE ^= m2
        m2 &= c6
        t ^= m2
        c6 ^= cE
        c6 ^= t
        m2 = mA
        mA = c6
        c6 = cE
        cE = ^t
        t = m3
        m3 &= mB
        m3 ^= cF
        mB ^= c7
        mB ^= m3
        cF |= t
        cF ^= c7
        t ^= mB
        c7 = cF
        cF |= t
        cF ^= m3
        m3 &= c7
        t ^= m3
        c7 ^= cF
        c7 ^= t
        m3 = mB
        mB = c7
        c7 = cF
        cF = ^t
        t = c2
        c2 &= cA
        c2 ^= mE
        cA ^= m6
        cA ^= c2
        mE |= t
        mE ^= m6
        t ^= cA
        m6 = mE
        mE |= t
        mE ^= c2
        c2 &= m6
        t ^= c2
        m6 ^= mE
        m6 ^= t
        c2 = cA
        cA = m6
        m6 = mE
        mE = ^t
        t = c3
        c3 &= cB
        c3 ^= mF
        cB ^= m7
        cB ^= c3
        mF |= t
        mF ^= m7
        t ^= cB
        m7 = mF
        mF |= t
        mF ^= c3
        c3 &= m7
        t ^= c3
        m7 ^= mF
        m7 ^= t
        c3 = cB
        cB = m7
        m7 = mF
        mF = ^t
        m0 = (m0 << 13) | (m0 >> (32 - 13))
        c8 = (c8 << 3) | (c8 >> (32 - 3))
        c5 ^= m0 ^ c8
        mD ^= c8 ^ (m0 << 3)
        c5 = (c5 << 1) | (c5 >> (32 - 1))
        mD = (mD << 7) | (mD >> (32 - 7))
        m0 ^= c5 ^ mD
        c8 ^= mD ^ (c5 << 7)
        m0 = (m0 << 5) | (m0 >> (32 - 5))
        c8 = (c8 << 22) | (c8 >> (32 - 22))
        m1 = (m1 << 13) | (m1 >> (32 - 13))
        c9 = (c9 << 3) | (c9 >> (32 - 3))
        m4 ^= m1 ^ c9
        cE ^= c9 ^ (m1 << 3)
        m4 = (m4 << 1) | (m4 >> (32 - 1))
        cE = (cE << 7) | (cE >> (32 - 7))
        m1 ^= m4 ^ cE
        c9 ^= cE ^ (m4 << 7)
        m1 = (m1 << 5) | (m1 >> (32 - 5))
        c9 = (c9 << 22) | (c9 >> (32 - 22))
        c0 = (c0 << 13) | (c0 >> (32 - 13))
        mA = (mA << 3) | (mA >> (32 - 3))
        m5 ^= c0 ^ mA
        cF ^= mA ^ (c0 << 3)
        m5 = (m5 << 1) | (m5 >> (32 - 1))
        cF = (cF << 7) | (cF >> (32 - 7))
        c0 ^= m5 ^ cF
        mA ^= cF ^ (m5 << 7)
        c0 = (c0 << 5) | (c0 >> (32 - 5))
        mA = (mA << 22) | (mA >> (32 - 22))
        c1 = (c1 << 13) | (c1 >> (32 - 13))
        mB = (mB << 3) | (mB >> (32 - 3))
        c6 ^= c1 ^ mB
        mE ^= mB ^ (c1 << 3)
        c6 = (c6 << 1) | (c6 >> (32 - 1))
        mE = (mE << 7) | (mE >> (32 - 7))
        c1 ^= c6 ^ mE
        mB ^= mE ^ (c6 << 7)
        c1 = (c1 << 5) | (c1 >> (32 - 5))
        mB = (mB << 22) | (mB >> (32 - 22))
        m2 = (m2 << 13) | (m2 >> (32 - 13))
        cA = (cA << 3) | (cA >> (32 - 3))
        c7 ^= m2 ^ cA
        mF ^= cA ^ (m2 << 3)
        c7 = (c7 << 1) | (c7 >> (32 - 1))
        mF = (mF << 7) | (mF >> (32 - 7))
        m2 ^= c7 ^ mF
        cA ^= mF ^ (c7 << 7)
        m2 = (m2 << 5) | (m2 >> (32 - 5))
        cA = (cA << 22) | (cA >> (32 - 22))
        m3 = (m3 << 13) | (m3 >> (32 - 13))
        cB = (cB << 3) | (cB >> (32 - 3))
        m6 ^= m3 ^ cB
        cC ^= cB ^ (m3 << 3)
        m6 = (m6 << 1) | (m6 >> (32 - 1))
        cC = (cC << 7) | (cC >> (32 - 7))
        m3 ^= m6 ^ cC
        cB ^= cC ^ (m6 << 7)
        m3 = (m3 << 5) | (m3 >> (32 - 5))
        cB = (cB << 22) | (cB >> (32 - 22))
        c2 = (c2 << 13) | (c2 >> (32 - 13))
        m8 = (m8 << 3) | (m8 >> (32 - 3))
        m7 ^= c2 ^ m8
        cD ^= m8 ^ (c2 << 3)
        m7 = (m7 << 1) | (m7 >> (32 - 1))
        cD = (cD << 7) | (cD >> (32 - 7))
        c2 ^= m7 ^ cD
        m8 ^= cD ^ (m7 << 7)
        c2 = (c2 << 5) | (c2 >> (32 - 5))
        m8 = (m8 << 22) | (m8 >> (32 - 22))
        c3 = (c3 << 13) | (c3 >> (32 - 13))
        m9 = (m9 << 3) | (m9 >> (32 - 3))
        c4 ^= c3 ^ m9
        mC ^= m9 ^ (c3 << 3)
        c4 = (c4 << 1) | (c4 >> (32 - 1))
        mC = (mC << 7) | (mC >> (32 - 7))
        c3 ^= c4 ^ mC
        m9 ^= mC ^ (c4 << 7)
        c3 = (c3 << 5) | (c3 >> (32 - 5))
        m9 = (m9 << 22) | (m9 >> (32 - 22))
        m0 = (m0 << 13) | (m0 >> (32 - 13))
        m3 = (m3 << 3) | (m3 >> (32 - 3))
        c0 ^= m0 ^ m3
        c3 ^= m3 ^ (m0 << 3)
        c0 = (c0 << 1) | (c0 >> (32 - 1))
        c3 = (c3 << 7) | (c3 >> (32 - 7))
        m0 ^= c0 ^ c3
        m3 ^= c3 ^ (c0 << 7)
        m0 = (m0 << 5) | (m0 >> (32 - 5))
        m3 = (m3 << 22) | (m3 >> (32 - 22))
        m8 = (m8 << 13) | (m8 >> (32 - 13))
        mB = (mB << 3) | (mB >> (32 - 3))
        c9 ^= m8 ^ mB
        cA ^= mB ^ (m8 << 3)
        c9 = (c9 << 1) | (c9 >> (32 - 1))
        cA = (cA << 7) | (cA >> (32 - 7))
        m8 ^= c9 ^ cA
        mB ^= cA ^ (c9 << 7)
        m8 = (m8 << 5) | (m8 >> (32 - 5))
        mB = (mB << 22) | (mB >> (32 - 22))
        c5 = (c5 << 13) | (c5 >> (32 - 13))
        c6 = (c6 << 3) | (c6 >> (32 - 3))
        m5 ^= c5 ^ c6
        m6 ^= c6 ^ (c5 << 3)
        m5 = (m5 << 1) | (m5 >> (32 - 1))
        m6 = (m6 << 7) | (m6 >> (32 - 7))
        c5 ^= m5 ^ m6
        c6 ^= m6 ^ (m5 << 7)
        c5 = (c5 << 5) | (c5 >> (32 - 5))
        c6 = (c6 << 22) | (c6 >> (32 - 22))
        cD = (cD << 13) | (cD >> (32 - 13))
        cE = (cE << 3) | (cE >> (32 - 3))
        mC ^= cD ^ cE
        mF ^= cE ^ (cD << 3)
        mC = (mC << 1) | (mC >> (32 - 1))
        mF = (mF << 7) | (mF >> (32 - 7))
        cD ^= mC ^ mF
        cE ^= mF ^ (mC << 7)
        cD = (cD << 5) | (cD >> (32 - 5))
        cE = (cE << 22) | (cE >> (32 - 22))
    }

    d.s[0xF] ^= cB
    d.s[0xE] ^= cA
    d.s[0xD] ^= mB
    d.s[0xC] ^= mA
    d.s[0xB] ^= c9
    d.s[0xA] ^= c8
    d.s[0x9] ^= m9
    d.s[0x8] ^= m8
    d.s[0x7] ^= c3
    d.s[0x6] ^= c2
    d.s[0x5] ^= m3
    d.s[0x4] ^= m2
    d.s[0x3] ^= c1
    d.s[0x2] ^= c0
    d.s[0x1] ^= m1
    d.s[0x0] ^= m0
}

func (d *digest512) processFinal(
    b0, b1, b2, b3 uint32,
    b4, b5, b6, b7 uint32,
) {
    var rp = T512_0[b0]

    var m0 = rp[0x0]
    var m1 = rp[0x1]
    var m2 = rp[0x2]
    var m3 = rp[0x3]
    var m4 = rp[0x4]
    var m5 = rp[0x5]
    var m6 = rp[0x6]
    var m7 = rp[0x7]
    var m8 = rp[0x8]
    var m9 = rp[0x9]
    var mA = rp[0xA]
    var mB = rp[0xB]
    var mC = rp[0xC]
    var mD = rp[0xD]
    var mE = rp[0xE]
    var mF = rp[0xF]

    rp = T512_1[b1]
    m0 ^= rp[0x0]
    m1 ^= rp[0x1]
    m2 ^= rp[0x2]
    m3 ^= rp[0x3]
    m4 ^= rp[0x4]
    m5 ^= rp[0x5]
    m6 ^= rp[0x6]
    m7 ^= rp[0x7]
    m8 ^= rp[0x8]
    m9 ^= rp[0x9]
    mA ^= rp[0xA]
    mB ^= rp[0xB]
    mC ^= rp[0xC]
    mD ^= rp[0xD]
    mE ^= rp[0xE]
    mF ^= rp[0xF]
    rp = T512_2[b2]
    m0 ^= rp[0x0]
    m1 ^= rp[0x1]
    m2 ^= rp[0x2]
    m3 ^= rp[0x3]
    m4 ^= rp[0x4]
    m5 ^= rp[0x5]
    m6 ^= rp[0x6]
    m7 ^= rp[0x7]
    m8 ^= rp[0x8]
    m9 ^= rp[0x9]
    mA ^= rp[0xA]
    mB ^= rp[0xB]
    mC ^= rp[0xC]
    mD ^= rp[0xD]
    mE ^= rp[0xE]
    mF ^= rp[0xF]
    rp = T512_3[b3]
    m0 ^= rp[0x0]
    m1 ^= rp[0x1]
    m2 ^= rp[0x2]
    m3 ^= rp[0x3]
    m4 ^= rp[0x4]
    m5 ^= rp[0x5]
    m6 ^= rp[0x6]
    m7 ^= rp[0x7]
    m8 ^= rp[0x8]
    m9 ^= rp[0x9]
    mA ^= rp[0xA]
    mB ^= rp[0xB]
    mC ^= rp[0xC]
    mD ^= rp[0xD]
    mE ^= rp[0xE]
    mF ^= rp[0xF]
    rp = T512_4[b4]
    m0 ^= rp[0x0]
    m1 ^= rp[0x1]
    m2 ^= rp[0x2]
    m3 ^= rp[0x3]
    m4 ^= rp[0x4]
    m5 ^= rp[0x5]
    m6 ^= rp[0x6]
    m7 ^= rp[0x7]
    m8 ^= rp[0x8]
    m9 ^= rp[0x9]
    mA ^= rp[0xA]
    mB ^= rp[0xB]
    mC ^= rp[0xC]
    mD ^= rp[0xD]
    mE ^= rp[0xE]
    mF ^= rp[0xF]
    rp = T512_5[b5]
    m0 ^= rp[0x0]
    m1 ^= rp[0x1]
    m2 ^= rp[0x2]
    m3 ^= rp[0x3]
    m4 ^= rp[0x4]
    m5 ^= rp[0x5]
    m6 ^= rp[0x6]
    m7 ^= rp[0x7]
    m8 ^= rp[0x8]
    m9 ^= rp[0x9]
    mA ^= rp[0xA]
    mB ^= rp[0xB]
    mC ^= rp[0xC]
    mD ^= rp[0xD]
    mE ^= rp[0xE]
    mF ^= rp[0xF]
    rp = T512_6[b6]
    m0 ^= rp[0x0]
    m1 ^= rp[0x1]
    m2 ^= rp[0x2]
    m3 ^= rp[0x3]
    m4 ^= rp[0x4]
    m5 ^= rp[0x5]
    m6 ^= rp[0x6]
    m7 ^= rp[0x7]
    m8 ^= rp[0x8]
    m9 ^= rp[0x9]
    mA ^= rp[0xA]
    mB ^= rp[0xB]
    mC ^= rp[0xC]
    mD ^= rp[0xD]
    mE ^= rp[0xE]
    mF ^= rp[0xF]
    rp = T512_7[b7]
    m0 ^= rp[0x0]
    m1 ^= rp[0x1]
    m2 ^= rp[0x2]
    m3 ^= rp[0x3]
    m4 ^= rp[0x4]
    m5 ^= rp[0x5]
    m6 ^= rp[0x6]
    m7 ^= rp[0x7]
    m8 ^= rp[0x8]
    m9 ^= rp[0x9]
    mA ^= rp[0xA]
    mB ^= rp[0xB]
    mC ^= rp[0xC]
    mD ^= rp[0xD]
    mE ^= rp[0xE]
    mF ^= rp[0xF]

    var c0 = d.s[0x0]
    var c1 = d.s[0x1]
    var c2 = d.s[0x2]
    var c3 = d.s[0x3]
    var c4 = d.s[0x4]
    var c5 = d.s[0x5]
    var c6 = d.s[0x6]
    var c7 = d.s[0x7]
    var c8 = d.s[0x8]
    var c9 = d.s[0x9]
    var cA = d.s[0xA]
    var cB = d.s[0xB]
    var cC = d.s[0xC]
    var cD = d.s[0xD]
    var cE = d.s[0xE]
    var cF = d.s[0xF]
    var t uint32

    for r := 0; r < 12; r++ {
        m0 ^= ALPHA_F512[0x00]
        m1 ^= ALPHA_F512[0x01] ^ uint32(r)
        c0 ^= ALPHA_F512[0x02]
        c1 ^= ALPHA_F512[0x03]
        m2 ^= ALPHA_F512[0x04]
        m3 ^= ALPHA_F512[0x05]
        c2 ^= ALPHA_F512[0x06]
        c3 ^= ALPHA_F512[0x07]
        c4 ^= ALPHA_F512[0x08]
        c5 ^= ALPHA_F512[0x09]
        m4 ^= ALPHA_F512[0x0A]
        m5 ^= ALPHA_F512[0x0B]
        c6 ^= ALPHA_F512[0x0C]
        c7 ^= ALPHA_F512[0x0D]
        m6 ^= ALPHA_F512[0x0E]
        m7 ^= ALPHA_F512[0x0F]
        m8 ^= ALPHA_F512[0x10]
        m9 ^= ALPHA_F512[0x11]
        c8 ^= ALPHA_F512[0x12]
        c9 ^= ALPHA_F512[0x13]
        mA ^= ALPHA_F512[0x14]
        mB ^= ALPHA_F512[0x15]
        cA ^= ALPHA_F512[0x16]
        cB ^= ALPHA_F512[0x17]
        cC ^= ALPHA_F512[0x18]
        cD ^= ALPHA_F512[0x19]
        mC ^= ALPHA_F512[0x1A]
        mD ^= ALPHA_F512[0x1B]
        cE ^= ALPHA_F512[0x1C]
        cF ^= ALPHA_F512[0x1D]
        mE ^= ALPHA_F512[0x1E]
        mF ^= ALPHA_F512[0x1F]
        t = m0
        m0 &= m8
        m0 ^= cC
        m8 ^= c4
        m8 ^= m0
        cC |= t
        cC ^= c4
        t ^= m8
        c4 = cC
        cC |= t
        cC ^= m0
        m0 &= c4
        t ^= m0
        c4 ^= cC
        c4 ^= t
        m0 = m8
        m8 = c4
        c4 = cC
        cC = ^t
        t = m1
        m1 &= m9
        m1 ^= cD
        m9 ^= c5
        m9 ^= m1
        cD |= t
        cD ^= c5
        t ^= m9
        c5 = cD
        cD |= t
        cD ^= m1
        m1 &= c5
        t ^= m1
        c5 ^= cD
        c5 ^= t
        m1 = m9
        m9 = c5
        c5 = cD
        cD = ^t
        t = c0
        c0 &= c8
        c0 ^= mC
        c8 ^= m4
        c8 ^= c0
        mC |= t
        mC ^= m4
        t ^= c8
        m4 = mC
        mC |= t
        mC ^= c0
        c0 &= m4
        t ^= c0
        m4 ^= mC
        m4 ^= t
        c0 = c8
        c8 = m4
        m4 = mC
        mC = ^t
        t = c1
        c1 &= c9
        c1 ^= mD
        c9 ^= m5
        c9 ^= c1
        mD |= t
        mD ^= m5
        t ^= c9
        m5 = mD
        mD |= t
        mD ^= c1
        c1 &= m5
        t ^= c1
        m5 ^= mD
        m5 ^= t
        c1 = c9
        c9 = m5
        m5 = mD
        mD = ^t
        t = m2
        m2 &= mA
        m2 ^= cE
        mA ^= c6
        mA ^= m2
        cE |= t
        cE ^= c6
        t ^= mA
        c6 = cE
        cE |= t
        cE ^= m2
        m2 &= c6
        t ^= m2
        c6 ^= cE
        c6 ^= t
        m2 = mA
        mA = c6
        c6 = cE
        cE = ^t
        t = m3
        m3 &= mB
        m3 ^= cF
        mB ^= c7
        mB ^= m3
        cF |= t
        cF ^= c7
        t ^= mB
        c7 = cF
        cF |= t
        cF ^= m3
        m3 &= c7
        t ^= m3
        c7 ^= cF
        c7 ^= t
        m3 = mB
        mB = c7
        c7 = cF
        cF = ^t
        t = c2
        c2 &= cA
        c2 ^= mE
        cA ^= m6
        cA ^= c2
        mE |= t
        mE ^= m6
        t ^= cA
        m6 = mE
        mE |= t
        mE ^= c2
        c2 &= m6
        t ^= c2
        m6 ^= mE
        m6 ^= t
        c2 = cA
        cA = m6
        m6 = mE
        mE = ^t
        t = c3
        c3 &= cB
        c3 ^= mF
        cB ^= m7
        cB ^= c3
        mF |= t
        mF ^= m7
        t ^= cB
        m7 = mF
        mF |= t
        mF ^= c3
        c3 &= m7
        t ^= c3
        m7 ^= mF
        m7 ^= t
        c3 = cB
        cB = m7
        m7 = mF
        mF = ^t
        m0 = (m0 << 13) | (m0 >> (32 - 13))
        c8 = (c8 << 3) | (c8 >> (32 - 3))
        c5 ^= m0 ^ c8
        mD ^= c8 ^ (m0 << 3)
        c5 = (c5 << 1) | (c5 >> (32 - 1))
        mD = (mD << 7) | (mD >> (32 - 7))
        m0 ^= c5 ^ mD
        c8 ^= mD ^ (c5 << 7)
        m0 = (m0 << 5) | (m0 >> (32 - 5))
        c8 = (c8 << 22) | (c8 >> (32 - 22))
        m1 = (m1 << 13) | (m1 >> (32 - 13))
        c9 = (c9 << 3) | (c9 >> (32 - 3))
        m4 ^= m1 ^ c9
        cE ^= c9 ^ (m1 << 3)
        m4 = (m4 << 1) | (m4 >> (32 - 1))
        cE = (cE << 7) | (cE >> (32 - 7))
        m1 ^= m4 ^ cE
        c9 ^= cE ^ (m4 << 7)
        m1 = (m1 << 5) | (m1 >> (32 - 5))
        c9 = (c9 << 22) | (c9 >> (32 - 22))
        c0 = (c0 << 13) | (c0 >> (32 - 13))
        mA = (mA << 3) | (mA >> (32 - 3))
        m5 ^= c0 ^ mA
        cF ^= mA ^ (c0 << 3)
        m5 = (m5 << 1) | (m5 >> (32 - 1))
        cF = (cF << 7) | (cF >> (32 - 7))
        c0 ^= m5 ^ cF
        mA ^= cF ^ (m5 << 7)
        c0 = (c0 << 5) | (c0 >> (32 - 5))
        mA = (mA << 22) | (mA >> (32 - 22))
        c1 = (c1 << 13) | (c1 >> (32 - 13))
        mB = (mB << 3) | (mB >> (32 - 3))
        c6 ^= c1 ^ mB
        mE ^= mB ^ (c1 << 3)
        c6 = (c6 << 1) | (c6 >> (32 - 1))
        mE = (mE << 7) | (mE >> (32 - 7))
        c1 ^= c6 ^ mE
        mB ^= mE ^ (c6 << 7)
        c1 = (c1 << 5) | (c1 >> (32 - 5))
        mB = (mB << 22) | (mB >> (32 - 22))
        m2 = (m2 << 13) | (m2 >> (32 - 13))
        cA = (cA << 3) | (cA >> (32 - 3))
        c7 ^= m2 ^ cA
        mF ^= cA ^ (m2 << 3)
        c7 = (c7 << 1) | (c7 >> (32 - 1))
        mF = (mF << 7) | (mF >> (32 - 7))
        m2 ^= c7 ^ mF
        cA ^= mF ^ (c7 << 7)
        m2 = (m2 << 5) | (m2 >> (32 - 5))
        cA = (cA << 22) | (cA >> (32 - 22))
        m3 = (m3 << 13) | (m3 >> (32 - 13))
        cB = (cB << 3) | (cB >> (32 - 3))
        m6 ^= m3 ^ cB
        cC ^= cB ^ (m3 << 3)
        m6 = (m6 << 1) | (m6 >> (32 - 1))
        cC = (cC << 7) | (cC >> (32 - 7))
        m3 ^= m6 ^ cC
        cB ^= cC ^ (m6 << 7)
        m3 = (m3 << 5) | (m3 >> (32 - 5))
        cB = (cB << 22) | (cB >> (32 - 22))
        c2 = (c2 << 13) | (c2 >> (32 - 13))
        m8 = (m8 << 3) | (m8 >> (32 - 3))
        m7 ^= c2 ^ m8
        cD ^= m8 ^ (c2 << 3)
        m7 = (m7 << 1) | (m7 >> (32 - 1))
        cD = (cD << 7) | (cD >> (32 - 7))
        c2 ^= m7 ^ cD
        m8 ^= cD ^ (m7 << 7)
        c2 = (c2 << 5) | (c2 >> (32 - 5))
        m8 = (m8 << 22) | (m8 >> (32 - 22))
        c3 = (c3 << 13) | (c3 >> (32 - 13))
        m9 = (m9 << 3) | (m9 >> (32 - 3))
        c4 ^= c3 ^ m9
        mC ^= m9 ^ (c3 << 3)
        c4 = (c4 << 1) | (c4 >> (32 - 1))
        mC = (mC << 7) | (mC >> (32 - 7))
        c3 ^= c4 ^ mC
        m9 ^= mC ^ (c4 << 7)
        c3 = (c3 << 5) | (c3 >> (32 - 5))
        m9 = (m9 << 22) | (m9 >> (32 - 22))
        m0 = (m0 << 13) | (m0 >> (32 - 13))
        m3 = (m3 << 3) | (m3 >> (32 - 3))
        c0 ^= m0 ^ m3
        c3 ^= m3 ^ (m0 << 3)
        c0 = (c0 << 1) | (c0 >> (32 - 1))
        c3 = (c3 << 7) | (c3 >> (32 - 7))
        m0 ^= c0 ^ c3
        m3 ^= c3 ^ (c0 << 7)
        m0 = (m0 << 5) | (m0 >> (32 - 5))
        m3 = (m3 << 22) | (m3 >> (32 - 22))
        m8 = (m8 << 13) | (m8 >> (32 - 13))
        mB = (mB << 3) | (mB >> (32 - 3))
        c9 ^= m8 ^ mB
        cA ^= mB ^ (m8 << 3)
        c9 = (c9 << 1) | (c9 >> (32 - 1))
        cA = (cA << 7) | (cA >> (32 - 7))
        m8 ^= c9 ^ cA
        mB ^= cA ^ (c9 << 7)
        m8 = (m8 << 5) | (m8 >> (32 - 5))
        mB = (mB << 22) | (mB >> (32 - 22))
        c5 = (c5 << 13) | (c5 >> (32 - 13))
        c6 = (c6 << 3) | (c6 >> (32 - 3))
        m5 ^= c5 ^ c6
        m6 ^= c6 ^ (c5 << 3)
        m5 = (m5 << 1) | (m5 >> (32 - 1))
        m6 = (m6 << 7) | (m6 >> (32 - 7))
        c5 ^= m5 ^ m6
        c6 ^= m6 ^ (m5 << 7)
        c5 = (c5 << 5) | (c5 >> (32 - 5))
        c6 = (c6 << 22) | (c6 >> (32 - 22))
        cD = (cD << 13) | (cD >> (32 - 13))
        cE = (cE << 3) | (cE >> (32 - 3))
        mC ^= cD ^ cE
        mF ^= cE ^ (cD << 3)
        mC = (mC << 1) | (mC >> (32 - 1))
        mF = (mF << 7) | (mF >> (32 - 7))
        cD ^= mC ^ mF
        cE ^= mF ^ (mC << 7)
        cD = (cD << 5) | (cD >> (32 - 5))
        cE = (cE << 22) | (cE >> (32 - 22))
    }

    d.s[0xF] ^= cB
    d.s[0xE] ^= cA
    d.s[0xD] ^= mB
    d.s[0xC] ^= mA
    d.s[0xB] ^= c9
    d.s[0xA] ^= c8
    d.s[0x9] ^= m9
    d.s[0x8] ^= m8
    d.s[0x7] ^= c3
    d.s[0x6] ^= c2
    d.s[0x5] ^= m3
    d.s[0x4] ^= m2
    d.s[0x3] ^= c1
    d.s[0x2] ^= c0
    d.s[0x1] ^= m1
    d.s[0x0] ^= m0
}
