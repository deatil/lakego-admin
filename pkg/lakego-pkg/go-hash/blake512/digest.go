package blake512

const (
    // The size of BLAKE-512 hash in bytes.
    Size = 64

    // The size of BLAKE-384 hash in bytes.
    Size384 = 48

    // The block size of the hash algorithm in bytes.
    BlockSize = 128
)

type digest struct {
    s     [4]uint64
    x     [BlockSize]byte
    nx    int
    len   uint64

    h      [8]uint64
    t      [2]uint64

    initVal [8]uint64
    hs      int
}

func newDigest(hs int, iv [8]uint64) *digest {
    d := new(digest)
    d.hs = hs
    d.initVal = iv
    d.Reset()

    return d
}

// Reset resets the state of digest. It leaves salt intact.
func (d *digest) Reset() {
    d.s = [4]uint64{}
    d.x = [BlockSize]byte{}
    d.nx = 0
    d.len = 0

    d.h = d.initVal
    d.t = [2]uint64{}
}

func (d *digest) Size() int {
    return d.hs
}

func (d *digest) BlockSize() int {
    return BlockSize
}

func (d *digest) Write(p []byte) (nn int, err error) {
    nn = len(p)

    plen := len(p)

    var limit = BlockSize
    for d.nx + plen >= limit {
        copy(d.x[d.nx:], p)

        d.compress(d.x[:])

        xx := limit - d.nx
        plen -= xx

        p = p[xx:]
        d.nx = 0
    }

    copy(d.x[d.nx:], p)
    d.nx += plen

    return
}

// Sum returns the checksum.
func (d *digest) Sum(in []byte) []byte {
    // Make a copy of d0 so that caller can keep writing and summing.
    d0 := *d
    sum := d0.checkSum()

    return append(in, sum[:]...)
}

func (d *digest) checkSum() (out []byte) {
    var ptr = d.nx
    var bitLen = uint64(ptr) << 3

    var th = d.t[1]
    var tl = d.t[0] + bitLen

    var tmpBuf [128]byte

    tmpBuf[ptr] = 0x80
    if ptr == 0 {
        d.t[0] = 0xFFFFFFFFFFFFFC00
        d.t[1] = 0xFFFFFFFFFFFFFFFF
    } else if d.t[0] == 0 {
        d.t[0] = 0xFFFFFFFFFFFFFC00 + bitLen
        d.t[1] --
    } else {
        d.t[0] -= 1024 - bitLen
    }

    if ptr < 112 {
        for i := ptr + 1; i < 112; i++ {
            tmpBuf[i] = 0x00
        }

        if d.hs == 64 {
            tmpBuf[111] |= 0x01
        }

        putu64(tmpBuf[112:], th)
        putu64(tmpBuf[120:], tl)

        d.Write(tmpBuf[ptr:])
    } else {
        for i := ptr + 1; i < 128; i++ {
            tmpBuf[i] = 0
        }

        d.Write(tmpBuf[ptr:])

        d.t[0] = 0xFFFFFFFFFFFFFC00
        d.t[1] = 0xFFFFFFFFFFFFFFFF

        for i := 0; i < 112; i++ {
            tmpBuf[i] = 0x00
        }

        if d.hs == 64 {
            tmpBuf[111] = 0x01
        }

        putu64(tmpBuf[112:], th)
        putu64(tmpBuf[120:], tl)

        d.Write(tmpBuf[:])
    }

    out = make([]byte, d.hs)

    putu64(out[0:], d.h[0])
    putu64(out[8:], d.h[1])
    putu64(out[16:], d.h[2])
    putu64(out[24:], d.h[3])
    putu64(out[32:], d.h[4])
    putu64(out[40:], d.h[5])

    if d.hs == 64 {
        putu64(out[48:], d.h[6])
        putu64(out[56:], d.h[7])
    }

    return
}

func (d *digest) compress(data []uint8) {
    d.t[0] += 1024
    tmp := ^0x3FF
    if (d.t[0] & uint64(tmp)) == 0 {
        d.t[1]++
    }

    var v0 = d.h[0]
    var v1 = d.h[1]
    var v2 = d.h[2]
    var v3 = d.h[3]
    var v4 = d.h[4]
    var v5 = d.h[5]
    var v6 = d.h[6]
    var v7 = d.h[7]
    var v8 = d.s[0] ^ 0x243F6A8885A308D3
    var v9 = d.s[1] ^ 0x13198A2E03707344
    var vA = d.s[2] ^ 0xA4093822299F31D0
    var vB = d.s[3] ^ 0x082EFA98EC4E6C89
    var vC = d.t[0] ^ 0x452821E638D01377
    var vD = d.t[0] ^ 0xBE5466CF34E90C6C
    var vE = d.t[1] ^ 0xC0AC29B7C97C50DD
    var vF = d.t[1] ^ 0x3F84D5B5B5470917

    var m [16]uint64

    for i := 0; i < 16; i++ {
        m[i] = getu64(data[8 * i:])
    }

    for r := 0; r < 16; r++ {
        var o0 = sigma[(r << 4) + 0x0]
        var o1 = sigma[(r << 4) + 0x1]

        v0 += v4 + (m[o0] ^ cb[o1])
        vC = circularRight(vC ^ v0, 32)
        v8 += vC
        v4 = circularRight(v4 ^ v8, 25)
        v0 += v4 + (m[o1] ^ cb[o0])
        vC = circularRight(vC ^ v0, 16)
        v8 += vC
        v4 = circularRight(v4 ^ v8, 11)
        o0 = sigma[(r << 4) + 0x2]
        o1 = sigma[(r << 4) + 0x3]
        v1 += v5 + (m[o0] ^ cb[o1])
        vD = circularRight(vD ^ v1, 32)
        v9 += vD
        v5 = circularRight(v5 ^ v9, 25)
        v1 += v5 + (m[o1] ^ cb[o0])
        vD = circularRight(vD ^ v1, 16)
        v9 += vD
        v5 = circularRight(v5 ^ v9, 11)
        o0 = sigma[(r << 4) + 0x4]
        o1 = sigma[(r << 4) + 0x5]
        v2 += v6 + (m[o0] ^ cb[o1])
        vE = circularRight(vE ^ v2, 32)
        vA += vE
        v6 = circularRight(v6 ^ vA, 25)
        v2 += v6 + (m[o1] ^ cb[o0])
        vE = circularRight(vE ^ v2, 16)
        vA += vE
        v6 = circularRight(v6 ^ vA, 11)
        o0 = sigma[(r << 4) + 0x6]
        o1 = sigma[(r << 4) + 0x7]
        v3 += v7 + (m[o0] ^ cb[o1])
        vF = circularRight(vF ^ v3, 32)
        vB += vF
        v7 = circularRight(v7 ^ vB, 25)
        v3 += v7 + (m[o1] ^ cb[o0])
        vF = circularRight(vF ^ v3, 16)
        vB += vF
        v7 = circularRight(v7 ^ vB, 11)
        o0 = sigma[(r << 4) + 0x8]
        o1 = sigma[(r << 4) + 0x9]
        v0 += v5 + (m[o0] ^ cb[o1])
        vF = circularRight(vF ^ v0, 32)
        vA += vF
        v5 = circularRight(v5 ^ vA, 25)
        v0 += v5 + (m[o1] ^ cb[o0])
        vF = circularRight(vF ^ v0, 16)
        vA += vF
        v5 = circularRight(v5 ^ vA, 11)
        o0 = sigma[(r << 4) + 0xA]
        o1 = sigma[(r << 4) + 0xB]
        v1 += v6 + (m[o0] ^ cb[o1])
        vC = circularRight(vC ^ v1, 32)
        vB += vC
        v6 = circularRight(v6 ^ vB, 25)
        v1 += v6 + (m[o1] ^ cb[o0])
        vC = circularRight(vC ^ v1, 16)
        vB += vC
        v6 = circularRight(v6 ^ vB, 11)
        o0 = sigma[(r << 4) + 0xC]
        o1 = sigma[(r << 4) + 0xD]
        v2 += v7 + (m[o0] ^ cb[o1])
        vD = circularRight(vD ^ v2, 32)
        v8 += vD
        v7 = circularRight(v7 ^ v8, 25)
        v2 += v7 + (m[o1] ^ cb[o0])
        vD = circularRight(vD ^ v2, 16)
        v8 += vD
        v7 = circularRight(v7 ^ v8, 11)
        o0 = sigma[(r << 4) + 0xE]
        o1 = sigma[(r << 4) + 0xF]
        v3 += v4 + (m[o0] ^ cb[o1])
        vE = circularRight(vE ^ v3, 32)
        v9 += vE
        v4 = circularRight(v4 ^ v9, 25)
        v3 += v4 + (m[o1] ^ cb[o0])
        vE = circularRight(vE ^ v3, 16)
        v9 += vE
        v4 = circularRight(v4 ^ v9, 11)
    }

    d.h[0] ^= d.s[0] ^ v0 ^ v8
    d.h[1] ^= d.s[1] ^ v1 ^ v9
    d.h[2] ^= d.s[2] ^ v2 ^ vA
    d.h[3] ^= d.s[3] ^ v3 ^ vB
    d.h[4] ^= d.s[0] ^ v4 ^ vC
    d.h[5] ^= d.s[1] ^ v5 ^ vD
    d.h[6] ^= d.s[2] ^ v6 ^ vE
    d.h[7] ^= d.s[3] ^ v7 ^ vF
}

func (d *digest) setSalt(s []byte) {
    if len(s) != 32 {
        panic("salt length must be 32 bytes")
    }

    ss := bytesToUint64s(s)
    copy(d.s[:], ss)
}
