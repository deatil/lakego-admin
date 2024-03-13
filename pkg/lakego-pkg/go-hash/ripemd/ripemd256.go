package ripemd

import (
    "hash"
    "math/bits"
)

const (
    // The size of the checksum in bytes.
    Size256 = 32

    // The block size of the hash algorithm in bytes.
    BlockSize256 = 64
)

// Sum256 returns checksum of the data.
func Sum256(data []byte) (sum [Size256]byte) {
    var h ripemd256digest
    h.Reset()
    h.Write(data)

    hash := h.Sum(nil)
    copy(sum[:], hash)
    return
}

type ripemd256digest struct {
    s  [8]uint32          // running context
    x  [BlockSize256]byte // temporary buffer
    nx int                // index into buffer
    tc uint64             // total count of bytes processed
}

func New256() hash.Hash {
    r := new(ripemd256digest)
    r.Reset()
    return r
}

func (r *ripemd256digest) Reset() {
    r.s[0], r.s[1], r.s[2], r.s[3], r.s[4], r.s[5], r.s[6], r.s[7] = s0, s1, s2, s3, s5, s6, s7, s8
    r.nx = 0
    r.tc = 0
}

func (r *ripemd256digest) Size() int {
    return Size256
}

func (r *ripemd256digest) BlockSize() int {
    return BlockSize256
}

func (d *ripemd256digest) Write(p []byte) (nn int, err error) {
    nn = len(p)
    d.tc += uint64(nn)
    if d.nx > 0 {
        n := len(p)
        if n > BlockSize256-d.nx {
            n = BlockSize256 - d.nx
        }
        for i := 0; i < n; i++ {
            d.x[d.nx+i] = p[i]
        }
        d.nx += n
        if d.nx == BlockSize256 {
            block256(d, d.x[0:])
            d.nx = 0
        }
        p = p[n:]
    }
    n := block256(d, p)
    p = p[n:]
    if len(p) > 0 {
        d.nx = copy(d.x[:], p)
    }
    return
}

func (d *ripemd256digest) Sum(in []byte) []byte {
    // Make a copy of d so that caller can keep writing and summing.
    d0 := *d
    hash := d0.checkSum()
    return append(in, hash[:]...)
}

func (d *ripemd256digest) checkSum() [Size256]byte {
    // Padding.  Add a 1 bit and 0 bits until 56 bytes mod 64.
    tc := d.tc
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

    var digest [Size256]byte
    for i, s := range d.s {
        digest[i*4] = byte(s)
        digest[i*4+1] = byte(s >> 8)
        digest[i*4+2] = byte(s >> 16)
        digest[i*4+3] = byte(s >> 24)
    }

    return digest
}

// work buffer indices and roll amounts for one line
var sbox256n0 = [64]uint{
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
    3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
    1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
}

var sbox256r0 = [64]uint{
    11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
    7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
    11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
    11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
}

// same for the other parallel one
var sbox256n1 = [64]uint{
    5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
    6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
    15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
    8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
}

var sbox256r1 = [64]uint{
    8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
    9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
    9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
    15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
}

func block256(md *ripemd256digest, p []byte) int {
    n := 0
    var x [16]uint32
    var alpha uint32
    for len(p) >= BlockSize256 {
        a, b, c, d := md.s[0], md.s[1], md.s[2], md.s[3]
        aa, bb, cc, dd := md.s[4], md.s[5], md.s[6], md.s[7]
        j := 0
        for i := 0; i < 16; i++ {
            x[i] = uint32(p[j]) | uint32(p[j+1])<<8 | uint32(p[j+2])<<16 | uint32(p[j+3])<<24
            j += 4
        }

        // round 1
        i := 0
        for i < 16 {
            alpha = a + (b ^ c ^ d) + x[sbox256n0[i]]
            s := int(sbox256r0[i])
            alpha = bits.RotateLeft32(alpha, s)
            a, b, c, d = d, alpha, b, c

            // parallel line
            alpha = aa + (cc ^ (dd & (bb ^ cc))) + x[sbox256n1[i]] + 0x50a28be6
            s = int(sbox256r1[i])
            alpha = bits.RotateLeft32(alpha, s)
            aa, bb, cc, dd = dd, alpha, bb, cc

            i++
        }

        t := a
        a = aa
        aa = t

        // round 2
        for i < 32 {
            alpha = a + (d ^ (b & (c ^ d))) + x[sbox256n0[i]] + 0x5a827999
            s := int(sbox256r0[i])
            alpha = bits.RotateLeft32(alpha, s)
            a, b, c, d = d, alpha, b, c

            // parallel line
            alpha = aa + (dd ^ (bb | ^cc)) + x[sbox256n1[i]] + 0x5c4dd124
            s = int(sbox256r1[i])
            alpha = bits.RotateLeft32(alpha, s)
            aa, bb, cc, dd = dd, alpha, bb, cc

            i++
        }

        t = b
        b = bb
        bb = t

        // round 3
        for i < 48 {
            alpha = a + (d ^ (b | ^c)) + x[sbox256n0[i]] + 0x6ed9eba1
            s := int(sbox256r0[i])
            alpha = bits.RotateLeft32(alpha, s)
            a, b, c, d = d, alpha, b, c

            // parallel line
            alpha = aa + (dd ^ (bb & (cc ^ dd))) + x[sbox256n1[i]] + 0x6d703ef3
            s = int(sbox256r1[i])
            alpha = bits.RotateLeft32(alpha, s)
            aa, bb, cc, dd = dd, alpha, bb, cc

            i++
        }

        t = c
        c = cc
        cc = t

        // round 4
        for i < 64 {
            alpha = a + (c ^ (d & (b ^ c))) + x[sbox256n0[i]] + 0x8f1bbcdc
            s := int(sbox256r0[i])
            alpha = bits.RotateLeft32(alpha, s)
            a, b, c, d = d, alpha, b, c

            // parallel line
            alpha = aa + (bb ^ cc ^ dd) + x[sbox256n1[i]]
            s = int(sbox256r1[i])
            alpha = bits.RotateLeft32(alpha, s)
            aa, bb, cc, dd = dd, alpha, bb, cc

            i++
        }

        t = d
        d = dd
        dd = t

        // combine results
        md.s[0] += a
        md.s[1] += b
        md.s[2] += c
        md.s[3] += d
        md.s[4] += aa
        md.s[5] += bb
        md.s[6] += cc
        md.s[7] += dd

        p = p[BlockSize256:]
        n += BlockSize256
    }
    return n
}
