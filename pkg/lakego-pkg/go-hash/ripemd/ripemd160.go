package ripemd

import (
    "hash"
    "math/bits"
)

const (
    // The size of the checksum in bytes.
    Size160 = 20

    // The block size of the hash algorithm in bytes.
    BlockSize160 = 64
)

// Sum160 returns checksum of the data.
func Sum160(data []byte) (sum [Size160]byte) {
    var h digest160
    h.Reset()
    h.Write(data)

    hash := h.Sum(nil)
    copy(sum[:], hash)
    return
}

// digest160 represents the partial evaluation of a checksum.
type digest160 struct {
    s   [5]uint32          // running context
    x   [BlockSize160]byte // temporary buffer
    nx  int                // index into x
    len uint64             // total count of bytes processed
}

// New160 returns a new hash.Hash computing the checksum.
func New160() hash.Hash {
    result := new(digest160)
    result.Reset()
    return result
}

// implement of hash.Hash
func (d *digest160) Reset() {
    d.s[0], d.s[1], d.s[2], d.s[3], d.s[4] = s0, s1, s2, s3, s4
    d.nx = 0
    d.len = 0
}

func (d *digest160) Size() int {
    return Size160
}

func (d *digest160) BlockSize() int {
    return BlockSize160
}

func (d *digest160) Write(p []byte) (nn int, err error) {
    nn = len(p)
    d.len += uint64(nn)
    if d.nx > 0 {
        n := len(p)
        if n > BlockSize160-d.nx {
            n = BlockSize160 - d.nx
        }
        for i := 0; i < n; i++ {
            d.x[d.nx+i] = p[i]
        }

        d.nx += n
        if d.nx == BlockSize160 {
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

func (d *digest160) Sum(in []byte) []byte {
    // Make a copy of d so that caller can keep writing and summing.
    d0 := *d
    hash := d0.checkSum()
    return append(in, hash[:]...)
}

func (d *digest160) checkSum() [Size160]byte {
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

    var digest [Size160]byte
    for i, s := range d.s {
        digest[i*4] = byte(s)
        digest[i*4+1] = byte(s >> 8)
        digest[i*4+2] = byte(s >> 16)
        digest[i*4+3] = byte(s >> 24)
    }

    return digest
}

func (md *digest160) block(p []byte) int {
    n := 0
    var x [16]uint32
    var alpha, beta uint32
    for len(p) >= BlockSize160 {
        a, b, c, d, e := md.s[0], md.s[1], md.s[2], md.s[3], md.s[4]
        aa, bb, cc, dd, ee := a, b, c, d, e
        j := 0
        for i := 0; i < 16; i++ {
            x[i] = uint32(p[j]) | uint32(p[j+1])<<8 | uint32(p[j+2])<<16 | uint32(p[j+3])<<24
            j += 4
        }

        // round 1
        i := 0
        for i < 16 {
            alpha = a + (b ^ c ^ d) + x[sbox160n0[i]]
            s := int(sbox160r0[i])
            alpha = bits.RotateLeft32(alpha, s) + e
            beta = bits.RotateLeft32(c, 10)
            a, b, c, d, e = e, alpha, b, beta, d

            // parallel line
            alpha = aa + (bb ^ (cc | ^dd)) + x[sbox160n1[i]] + 0x50a28be6
            s = int(sbox160r1[i])
            alpha = bits.RotateLeft32(alpha, s) + ee
            beta = bits.RotateLeft32(cc, 10)
            aa, bb, cc, dd, ee = ee, alpha, bb, beta, dd

            i++
        }

        // round 2
        for i < 32 {
            alpha = a + (b&c | ^b&d) + x[sbox160n0[i]] + 0x5a827999
            s := int(sbox160r0[i])
            alpha = bits.RotateLeft32(alpha, s) + e
            beta = bits.RotateLeft32(c, 10)
            a, b, c, d, e = e, alpha, b, beta, d

            // parallel line
            alpha = aa + (bb&dd | cc&^dd) + x[sbox160n1[i]] + 0x5c4dd124
            s = int(sbox160r1[i])
            alpha = bits.RotateLeft32(alpha, s) + ee
            beta = bits.RotateLeft32(cc, 10)
            aa, bb, cc, dd, ee = ee, alpha, bb, beta, dd

            i++
        }

        // round 3
        for i < 48 {
            alpha = a + (b | ^c ^ d) + x[sbox160n0[i]] + 0x6ed9eba1
            s := int(sbox160r0[i])
            alpha = bits.RotateLeft32(alpha, s) + e
            beta = bits.RotateLeft32(c, 10)
            a, b, c, d, e = e, alpha, b, beta, d

            // parallel line
            alpha = aa + (bb | ^cc ^ dd) + x[sbox160n1[i]] + 0x6d703ef3
            s = int(sbox160r1[i])
            alpha = bits.RotateLeft32(alpha, s) + ee
            beta = bits.RotateLeft32(cc, 10)
            aa, bb, cc, dd, ee = ee, alpha, bb, beta, dd

            i++
        }

        // round 4
        for i < 64 {
            alpha = a + (b&d | c&^d) + x[sbox160n0[i]] + 0x8f1bbcdc
            s := int(sbox160r0[i])
            alpha = bits.RotateLeft32(alpha, s) + e
            beta = bits.RotateLeft32(c, 10)
            a, b, c, d, e = e, alpha, b, beta, d

            // parallel line
            alpha = aa + (bb&cc | ^bb&dd) + x[sbox160n1[i]] + 0x7a6d76e9
            s = int(sbox160r1[i])
            alpha = bits.RotateLeft32(alpha, s) + ee
            beta = bits.RotateLeft32(cc, 10)
            aa, bb, cc, dd, ee = ee, alpha, bb, beta, dd

            i++
        }

        // round 5
        for i < 80 {
            alpha = a + (b ^ (c | ^d)) + x[sbox160n0[i]] + 0xa953fd4e
            s := int(sbox160r0[i])
            alpha = bits.RotateLeft32(alpha, s) + e
            beta = bits.RotateLeft32(c, 10)
            a, b, c, d, e = e, alpha, b, beta, d

            // parallel line
            alpha = aa + (bb ^ cc ^ dd) + x[sbox160n1[i]]
            s = int(sbox160r1[i])
            alpha = bits.RotateLeft32(alpha, s) + ee
            beta = bits.RotateLeft32(cc, 10)
            aa, bb, cc, dd, ee = ee, alpha, bb, beta, dd

            i++
        }

        // combine results
        dd += c + md.s[1]
        md.s[1] = md.s[2] + d + ee
        md.s[2] = md.s[3] + e + aa
        md.s[3] = md.s[4] + a + bb
        md.s[4] = md.s[0] + b + cc
        md.s[0] = dd

        p = p[BlockSize160:]
        n += BlockSize160
    }
    return n
}
