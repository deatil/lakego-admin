package ripemd

import (
    "hash"
    "math/bits"
)

const (
    // The size of the checksum in bytes.
    Size320 = 40

    // The block size of the hash algorithm in bytes.
    BlockSize320 = 64
)

// Sum320 returns checksum of the data.
func Sum320(data []byte) (sum [Size320]byte) {
    var h digest320
    h.Reset()
    h.Write(data)

    hash := h.Sum(nil)
    copy(sum[:], hash)
    return
}

type digest320 struct {
    s   [10]uint32         // running context
    x   [BlockSize320]byte // temporary buffer
    nx  int                // index into buffer
    len uint64             // total count of bytes processed
}

func New320() hash.Hash {
    d := new(digest320)
    d.Reset()
    return d
}

func (d *digest320) Reset() {
    d.s[0], d.s[1], d.s[2], d.s[3], d.s[4] = s0, s1, s2, s3, s4
    d.s[5], d.s[6], d.s[7], d.s[8], d.s[9] = s5, s6, s7, s8, s9
    d.nx = 0
    d.len = 0
}

func (d *digest320) Size() int {
    return Size320
}

func (d *digest320) BlockSize() int {
    return BlockSize320
}

func (d *digest320) Write(p []byte) (nn int, err error) {
    nn = len(p)
    d.len += uint64(nn)
    if d.nx > 0 {
        n := len(p)
        if n > BlockSize320-d.nx {
            n = BlockSize320 - d.nx
        }
        for i := 0; i < n; i++ {
            d.x[d.nx+i] = p[i]
        }
        d.nx += n
        if d.nx == BlockSize320 {
            d.block(d.x[0:])
            d.nx = 0
        }
        p = p[n:]
    }

    n := d.block(p)
    p = p[n:]
    if len(p) > 0 {
        d.nx = copy(d.x[:], p)
    }
    return
}

func (d *digest320) Sum(in []byte) []byte {
    // Make a copy of d so that caller can keep writing and summing.
    d0 := *d
    hash := d0.checkSum()
    return append(in, hash[:]...)
}

func (d *digest320) checkSum() [Size320]byte {
    // Padding.  Add a 1 bit and 0 bits until 56 bytes mod 64.
    tc := d.len
    var tmp [64]byte
    tmp[0] = 0x80
    if tc%64 < 56 {
        d.Write(tmp[0 : 56-tc%64])
    } else {
        d.Write(tmp[0 : 64+56-tc%64])
    }

    // Length in bits.
    tc <<= 3
    for i := uint(0); i < 8; i++ {
        tmp[i] = byte(tc >> (8 * i))
    }
    d.Write(tmp[0:8])

    if d.nx != 0 {
        panic("d.nx != 0")
    }

    var digest [Size320]byte
    for i, s := range d.s {
        digest[i*4] = byte(s)
        digest[i*4+1] = byte(s >> 8)
        digest[i*4+2] = byte(s >> 16)
        digest[i*4+3] = byte(s >> 24)
    }

    return digest
}

func (md *digest320) block(p []byte) int {
    n := 0
    var x [16]uint32
    var alpha, beta uint32
    for len(p) >= BlockSize320 {
        a, b, c, d, e := md.s[0], md.s[1], md.s[2], md.s[3], md.s[4]
        aa, bb, cc, dd, ee := md.s[5], md.s[6], md.s[7], md.s[8], md.s[9]
        j := 0
        for i := 0; i < 16; i++ {
            x[i] = uint32(p[j]) | uint32(p[j+1])<<8 | uint32(p[j+2])<<16 | uint32(p[j+3])<<24
            j += 4
        }

        // round 1
        i := 0
        for i < 16 {
            alpha = a + (b ^ c ^ d) + x[sbox320n0[i]]
            s := int(sbox320r0[i])
            alpha = bits.RotateLeft32(alpha, s) + e
            beta = bits.RotateLeft32(c, 10)
            a, b, c, d, e = e, alpha, b, beta, d

            // parallel line
            alpha = aa + (bb ^ (cc | ^dd)) + x[sbox320n1[i]] + 0x50a28be6
            s = int(sbox320r1[i])
            alpha = bits.RotateLeft32(alpha, s) + ee
            beta = bits.RotateLeft32(cc, 10)
            aa, bb, cc, dd, ee = ee, alpha, bb, beta, dd

            i++
        }

        t := b
        b = bb
        bb = t

        // round 2
        for i < 32 {
            alpha = a + (d ^ (b & (c ^ d))) + x[sbox320n0[i]] + 0x5a827999
            s := int(sbox320r0[i])
            alpha = bits.RotateLeft32(alpha, s) + e
            beta = bits.RotateLeft32(c, 10)
            a, b, c, d, e = e, alpha, b, beta, d

            // parallel line
            alpha = aa + (cc ^ (dd & (bb ^ cc))) + x[sbox320n1[i]] + 0x5c4dd124
            s = int(sbox320r1[i])
            alpha = bits.RotateLeft32(alpha, s) + ee
            beta = bits.RotateLeft32(cc, 10)
            aa, bb, cc, dd, ee = ee, alpha, bb, beta, dd

            i++
        }

        t = d
        d = dd
        dd = t

        // round 3
        for i < 48 {
            alpha = a + (d ^ (b | ^c)) + x[sbox320n0[i]] + 0x6ed9eba1
            s := int(sbox320r0[i])
            alpha = bits.RotateLeft32(alpha, s) + e
            beta = bits.RotateLeft32(c, 10)
            a, b, c, d, e = e, alpha, b, beta, d

            // parallel line
            alpha = aa + (dd ^ (bb | ^cc)) + x[sbox320n1[i]] + 0x6d703ef3
            s = int(sbox320r1[i])
            alpha = bits.RotateLeft32(alpha, s) + ee
            beta = bits.RotateLeft32(cc, 10)
            aa, bb, cc, dd, ee = ee, alpha, bb, beta, dd

            i++
        }

        t = a
        a = aa
        aa = t

        // round 4
        for i < 64 {
            alpha = a + (c ^ (d & (b ^ c))) + x[sbox320n0[i]] + 0x8f1bbcdc
            s := int(sbox320r0[i])
            alpha = bits.RotateLeft32(alpha, s) + e
            beta = bits.RotateLeft32(c, 10)
            a, b, c, d, e = e, alpha, b, beta, d

            // parallel line
            alpha = aa + (dd ^ (bb & (cc ^ dd))) + x[sbox320n1[i]] + 0x7a6d76e9
            s = int(sbox320r1[i])
            alpha = bits.RotateLeft32(alpha, s) + ee
            beta = bits.RotateLeft32(cc, 10)
            aa, bb, cc, dd, ee = ee, alpha, bb, beta, dd

            i++
        }

        t = c
        c = cc
        cc = t

        // round 5
        for i < 80 {
            alpha = a + (b ^ (c | ^d)) + x[sbox320n0[i]] + 0xa953fd4e
            s := int(sbox320r0[i])
            alpha = bits.RotateLeft32(alpha, s) + e
            beta = bits.RotateLeft32(c, 10)
            a, b, c, d, e = e, alpha, b, beta, d

            // parallel line
            alpha = aa + (bb ^ cc ^ dd) + x[sbox320n1[i]]
            s = int(sbox320r1[i])
            alpha = bits.RotateLeft32(alpha, s) + ee
            beta = bits.RotateLeft32(cc, 10)
            aa, bb, cc, dd, ee = ee, alpha, bb, beta, dd

            i++
        }

        t = e
        e = ee
        ee = t

        // combine results
        md.s[0] += a
        md.s[1] += b
        md.s[2] += c
        md.s[3] += d
        md.s[4] += e
        md.s[5] += aa
        md.s[6] += bb
        md.s[7] += cc
        md.s[8] += dd
        md.s[9] += ee

        p = p[BlockSize320:]
        n += BlockSize320
    }
    return n
}
