package ripemd

import (
    "math/bits"
)

const (
    // The size of the checksum in bytes.
    Size128 = 16

    // The block size of the hash algorithm in bytes.
    BlockSize128 = 64
)

type digest128 struct {
    s   [4]uint32
    x   [BlockSize128]byte
    nx  int
    len uint64
}

func newDigest128() *digest128 {
    d := new(digest128)
    d.Reset()
    return d
}

func (d *digest128) Reset() {
    d.s[0], d.s[1], d.s[2], d.s[3] = s0, s1, s2, s3
    d.nx = 0
    d.len = 0
}

func (d *digest128) Size() int {
    return Size128
}

func (d *digest128) BlockSize() int {
    return BlockSize128
}

func (d *digest128) Write(p []byte) (nn int, err error) {
    nn = len(p)
    d.len += uint64(nn)

    if d.nx > 0 {
        n := len(p)
        if n > BlockSize128-d.nx {
            n = BlockSize128 - d.nx
        }

        for i := 0; i < n; i++ {
            d.x[d.nx+i] = p[i]
        }

        d.nx += n
        if d.nx == BlockSize128 {
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

func (d *digest128) Sum(in []byte) []byte {
    // Make a copy of d so that caller can keep writing and summing.
    d0 := *d
    hash := d0.checkSum()
    return append(in, hash[:]...)
}

func (d *digest128) checkSum() [Size128]byte {
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

    var digest [Size128]byte
    for i, s := range d.s {
        digest[i*4] = byte(s)
        digest[i*4+1] = byte(s >> 8)
        digest[i*4+2] = byte(s >> 16)
        digest[i*4+3] = byte(s >> 24)
    }

    return digest
}

func (md *digest128) block(p []byte) int {
    var x [16]uint32
    var alpha uint32

    n := 0

    for len(p) >= BlockSize128 {
        a, b, c, d := md.s[0], md.s[1], md.s[2], md.s[3]
        aa, bb, cc, dd := a, b, c, d
        j := 0
        for i := 0; i < 16; i++ {
            x[i] = uint32(p[j]) | uint32(p[j+1])<<8 | uint32(p[j+2])<<16 | uint32(p[j+3])<<24
            j += 4
        }

        // round 1
        i := 0
        for i < 16 {
            alpha = a + (b ^ c ^ d) + x[sbox128n0[i]]
            s := int(sbox128r0[i])
            alpha = bits.RotateLeft32(alpha, s)
            a, b, c, d = d, alpha, b, c

            // parallel line
            alpha = aa + (cc ^ (dd & (bb ^ cc))) + x[sbox128n1[i]] + 0x50a28be6
            s = int(sbox128r1[i])
            alpha = bits.RotateLeft32(alpha, s)
            aa, bb, cc, dd = dd, alpha, bb, cc

            i++
        }

        // round 2
        for i < 32 {
            alpha = a + (d ^ (b & (c ^ d))) + x[sbox128n0[i]] + 0x5a827999
            s := int(sbox128r0[i])
            alpha = bits.RotateLeft32(alpha, s)
            a, b, c, d = d, alpha, b, c

            // parallel line
            alpha = aa + (dd ^ (bb | ^cc)) + x[sbox128n1[i]] + 0x5c4dd124
            s = int(sbox128r1[i])
            alpha = bits.RotateLeft32(alpha, s)
            aa, bb, cc, dd = dd, alpha, bb, cc

            i++
        }

        // round 3
        for i < 48 {
            alpha = a + (d ^ (b | ^c)) + x[sbox128n0[i]] + 0x6ed9eba1
            s := int(sbox128r0[i])
            alpha = bits.RotateLeft32(alpha, s)
            a, b, c, d = d, alpha, b, c

            // parallel line
            alpha = aa + (dd ^ (bb & (cc ^ dd))) + x[sbox128n1[i]] + 0x6d703ef3
            s = int(sbox128r1[i])
            alpha = bits.RotateLeft32(alpha, s)
            aa, bb, cc, dd = dd, alpha, bb, cc

            i++
        }

        // round 4
        for i < 64 {
            alpha = a + (c ^ (d & (b ^ c))) + x[sbox128n0[i]] + 0x8f1bbcdc
            s := int(sbox128r0[i])
            alpha = bits.RotateLeft32(alpha, s)
            a, b, c, d = d, alpha, b, c

            // parallel line
            alpha = aa + (bb ^ cc ^ dd) + x[sbox128n1[i]]
            s = int(sbox128r1[i])
            alpha = bits.RotateLeft32(alpha, s)
            aa, bb, cc, dd = dd, alpha, bb, cc

            i++
        }

        // combine results
        c = md.s[1] + c + dd
        md.s[1] = md.s[2] + d + aa
        md.s[2] = md.s[3] + a + bb
        md.s[3] = md.s[0] + b + cc
        md.s[0] = c

        p = p[BlockSize128:]
        n += BlockSize128
    }

    return n
}
