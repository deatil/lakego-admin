// Copyright (c) 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package edwards448

import (
    "errors"
    "crypto/subtle"
    "encoding/binary"
)

var (
    scZero = Scalar{[56]byte{
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    }}
    scOne = Scalar{[56]byte{
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    }}
    scMinusOne = Scalar{[56]byte{
        0xf2, 0x44, 0x58, 0xab, 0x92, 0xc2, 0x78, 0x23,
        0x55, 0x8f, 0xc5, 0x8d, 0x72, 0xc2, 0x6c, 0x21,
        0x90, 0x36, 0xd6, 0xae, 0x49, 0xdb, 0x4e, 0xc4,
        0xe9, 0x23, 0xca, 0x7c, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x3f,
    }}
)

// A Scalar is an integer modulo
//
//	l = 2^446 - 13818066809895115352007386748515426880336692474882178609894547503885
//
// which is the prime order of the edwards25519 group.
//
// This type works similarly to math/big.Int, and all arguments and
// receivers are allowed to alias.
//
// The zero value is a valid zero element.
type Scalar struct {
    // s is the Scalar value in little-endian. The value is always reduced
    // modulo l between operations.
    s [56]byte
}

func NewScalar() *Scalar {
    return &Scalar{}
}

func (s *Scalar) MulAdd(x, y, z *Scalar) *Scalar {
    scMulAdd(&s.s, &x.s, &y.s, &z.s)
    return s
}

func (s *Scalar) Add(x, y *Scalar) *Scalar {
    // s = 1 * x + y mod l
    scMulAdd(&s.s, &scOne.s, &x.s, &y.s)
    return s
}

func (s *Scalar) Sub(x, y *Scalar) *Scalar {
    // s = -1 * y + x mod l
    scMulAdd(&s.s, &scMinusOne.s, &y.s, &x.s)
    return s
}

func (s *Scalar) Negate(x *Scalar) *Scalar {
    // s = -1 * x + 0 mod l
    scMulAdd(&s.s, &scMinusOne.s, &x.s, &scZero.s)
    return s
}

func (s *Scalar) Mul(x, y *Scalar) *Scalar {
    // s = x * y + 0 mod l
    scMulAdd(&s.s, &x.s, &y.s, &scZero.s)
    return s
}

func (s *Scalar) Set(x *Scalar) *Scalar {
    s.s = x.s
    return s
}

// Equal returns 1 if s and t are equal, and 0 otherwise.
func (s *Scalar) Equal(t *Scalar) int {
    return subtle.ConstantTimeCompare(s.s[:], t.s[:])
}

// SetUniformBytes sets s = x mod l, where x is a 114-byte little-endian integer.
// If x is not of the right length, SetUniformBytes returns nil and an error,
// and the receiver is unchanged.
//
// SetUniformBytes can be used to set s to an uniformly distributed value given
// 64 uniformly distributed random bytes.
func (s *Scalar) SetUniformBytes(x []byte) (*Scalar, error) {
    if len(x) != 114 {
        return nil, errors.New("edwards448: invalid SetUniformBytes input length")
    }

    var wide [114]byte
    copy(wide[:], x)
    scReduce(&s.s, &wide)
    return s, nil
}

// SetCanonicalBytes sets s = x, where x is a 57-byte little-endian encoding of
// s, and returns s. If x is not a canonical encoding of s, SetCanonicalBytes
// returns nil and an error, and the receiver is unchanged.
func (s *Scalar) SetCanonicalBytes(x []byte) (*Scalar, error) {
    if len(x) != 57 {
        return nil, errors.New("edwards448: invalid SetBytesWithClamping input length")
    }

    var ss Scalar
    copy(ss.s[:], x)
    if x[56] != 0 || !isReduced(&ss) {
        return nil, errors.New("edwards448: invalid scalar encoding")
    }
    s.s = ss.s
    return s, nil
}

func isReduced(s *Scalar) bool {
    for i := len(s.s) - 1; i >= 0; i-- {
        switch {
        case s.s[i] > scMinusOne.s[i]:
            return false
        case s.s[i] < scMinusOne.s[i]:
            return true
        }
    }
    return true
}

// SetBytesWithClamping applies the buffer pruning described in RFC 8032,
// Section 5.2.5 (also known as clamping) and sets s to the result. The input
// must be 57 bytes, and it is not modified. If x is not of the right length,
// SetBytesWithClamping returns nil and an error, and the receiver is unchanged.
func (s *Scalar) SetBytesWithClamping(x []byte) (*Scalar, error) {
    if len(x) != 57 {
        return nil, errors.New("edwards448: invalid SetBytesWithClamping input length")
    }

    var wide [114]byte
    copy(wide[:], x)
    wide[0] &^= 0x03
    wide[55] |= 0x80
    wide[56] = 0
    scReduce(&s.s, &wide)
    return s, nil
}

func (s *Scalar) Bytes() [56]byte {
    return s.s
}

// Input:
//
//	a[0]+256*a[1]+...+256^31*a[55] = a
//	b[0]+256*b[1]+...+256^31*b[55] = b
//	c[0]+256*c[1]+...+256^31*c[55] = c
//
// Output:
//
//	s[0]+256*s[1]+...+256^31*s[55] = (ab+c) mod l
//	where l = 2^446 - 13818066809895115352007386748515426880336692474882178609894547503885.
func scMulAdd(s, a, b, c *[56]byte) {
    // [print("a%d := int64(a[%d]) | int64(a[%d])<<8 | int64(a[%d])<<16" % (i, i*3, i*3+1, i*3+2)) for i in range(19)]
    a0 := int64(a[0]) | int64(a[1])<<8 | int64(a[2])<<16
    a1 := int64(a[3]) | int64(a[4])<<8 | int64(a[5])<<16
    a2 := int64(a[6]) | int64(a[7])<<8 | int64(a[8])<<16
    a3 := int64(a[9]) | int64(a[10])<<8 | int64(a[11])<<16
    a4 := int64(a[12]) | int64(a[13])<<8 | int64(a[14])<<16
    a5 := int64(a[15]) | int64(a[16])<<8 | int64(a[17])<<16
    a6 := int64(a[18]) | int64(a[19])<<8 | int64(a[20])<<16
    a7 := int64(a[21]) | int64(a[22])<<8 | int64(a[23])<<16
    a8 := int64(a[24]) | int64(a[25])<<8 | int64(a[26])<<16
    a9 := int64(a[27]) | int64(a[28])<<8 | int64(a[29])<<16
    a10 := int64(a[30]) | int64(a[31])<<8 | int64(a[32])<<16
    a11 := int64(a[33]) | int64(a[34])<<8 | int64(a[35])<<16
    a12 := int64(a[36]) | int64(a[37])<<8 | int64(a[38])<<16
    a13 := int64(a[39]) | int64(a[40])<<8 | int64(a[41])<<16
    a14 := int64(a[42]) | int64(a[43])<<8 | int64(a[44])<<16
    a15 := int64(a[45]) | int64(a[46])<<8 | int64(a[47])<<16
    a16 := int64(a[48]) | int64(a[49])<<8 | int64(a[50])<<16
    a17 := int64(a[51]) | int64(a[52])<<8 | int64(a[53])<<16
    a18 := int64(a[54]) | int64(a[55])<<8

    // [print("b%d := int64(b[%d]) | int64(b[%d])<<8 | int64(b[%d])<<16" % (i, i*3, i*3+1, i*3+2)) for i in range(19)
    b0 := int64(b[0]) | int64(b[1])<<8 | int64(b[2])<<16
    b1 := int64(b[3]) | int64(b[4])<<8 | int64(b[5])<<16
    b2 := int64(b[6]) | int64(b[7])<<8 | int64(b[8])<<16
    b3 := int64(b[9]) | int64(b[10])<<8 | int64(b[11])<<16
    b4 := int64(b[12]) | int64(b[13])<<8 | int64(b[14])<<16
    b5 := int64(b[15]) | int64(b[16])<<8 | int64(b[17])<<16
    b6 := int64(b[18]) | int64(b[19])<<8 | int64(b[20])<<16
    b7 := int64(b[21]) | int64(b[22])<<8 | int64(b[23])<<16
    b8 := int64(b[24]) | int64(b[25])<<8 | int64(b[26])<<16
    b9 := int64(b[27]) | int64(b[28])<<8 | int64(b[29])<<16
    b10 := int64(b[30]) | int64(b[31])<<8 | int64(b[32])<<16
    b11 := int64(b[33]) | int64(b[34])<<8 | int64(b[35])<<16
    b12 := int64(b[36]) | int64(b[37])<<8 | int64(b[38])<<16
    b13 := int64(b[39]) | int64(b[40])<<8 | int64(b[41])<<16
    b14 := int64(b[42]) | int64(b[43])<<8 | int64(b[44])<<16
    b15 := int64(b[45]) | int64(b[46])<<8 | int64(b[47])<<16
    b16 := int64(b[48]) | int64(b[49])<<8 | int64(b[50])<<16
    b17 := int64(b[51]) | int64(b[52])<<8 | int64(b[53])<<16
    b18 := int64(b[54]) | int64(b[55])<<8

    // [print("c%d := int64(c[%d]) | int64(c[%d])<<8 | int64(c[%d])<<16" % (i, i*3, i*3+1, i*3+2)) for i in range(19)]
    c0 := int64(c[0]) | int64(c[1])<<8 | int64(c[2])<<16
    c1 := int64(c[3]) | int64(c[4])<<8 | int64(c[5])<<16
    c2 := int64(c[6]) | int64(c[7])<<8 | int64(c[8])<<16
    c3 := int64(c[9]) | int64(c[10])<<8 | int64(c[11])<<16
    c4 := int64(c[12]) | int64(c[13])<<8 | int64(c[14])<<16
    c5 := int64(c[15]) | int64(c[16])<<8 | int64(c[17])<<16
    c6 := int64(c[18]) | int64(c[19])<<8 | int64(c[20])<<16
    c7 := int64(c[21]) | int64(c[22])<<8 | int64(c[23])<<16
    c8 := int64(c[24]) | int64(c[25])<<8 | int64(c[26])<<16
    c9 := int64(c[27]) | int64(c[28])<<8 | int64(c[29])<<16
    c10 := int64(c[30]) | int64(c[31])<<8 | int64(c[32])<<16
    c11 := int64(c[33]) | int64(c[34])<<8 | int64(c[35])<<16
    c12 := int64(c[36]) | int64(c[37])<<8 | int64(c[38])<<16
    c13 := int64(c[39]) | int64(c[40])<<8 | int64(c[41])<<16
    c14 := int64(c[42]) | int64(c[43])<<8 | int64(c[44])<<16
    c15 := int64(c[45]) | int64(c[46])<<8 | int64(c[47])<<16
    c16 := int64(c[48]) | int64(c[49])<<8 | int64(c[50])<<16
    c17 := int64(c[51]) | int64(c[52])<<8 | int64(c[53])<<16
    c18 := int64(c[54]) | int64(c[55])<<8
    var c19, c20, c21, c22, c23, c24, c25, c26, c27, c28, c29, c30, c31, c32, c33, c34, c35, c36 int64

    s0 := c0 + a0*b0
    s1 := c1 + a0*b1 + a1*b0
    s2 := c2 + a0*b2 + a1*b1 + a2*b0
    s3 := c3 + a0*b3 + a1*b2 + a2*b1 + a3*b0
    s4 := c4 + a0*b4 + a1*b3 + a2*b2 + a3*b1 + a4*b0
    s5 := c5 + a0*b5 + a1*b4 + a2*b3 + a3*b2 + a4*b1 + a5*b0
    s6 := c6 + a0*b6 + a1*b5 + a2*b4 + a3*b3 + a4*b2 + a5*b1 + a6*b0
    s7 := c7 + a0*b7 + a1*b6 + a2*b5 + a3*b4 + a4*b3 + a5*b2 + a6*b1 + a7*b0
    s8 := c8 + a0*b8 + a1*b7 + a2*b6 + a3*b5 + a4*b4 + a5*b3 + a6*b2 + a7*b1 + a8*b0
    s9 := c9 + a0*b9 + a1*b8 + a2*b7 + a3*b6 + a4*b5 + a5*b4 + a6*b3 + a7*b2 + a8*b1 + a9*b0
    s10 := c10 + a0*b10 + a1*b9 + a2*b8 + a3*b7 + a4*b6 + a5*b5 + a6*b4 + a7*b3 + a8*b2 + a9*b1 + a10*b0
    s11 := c11 + a0*b11 + a1*b10 + a2*b9 + a3*b8 + a4*b7 + a5*b6 + a6*b5 + a7*b4 + a8*b3 + a9*b2 + a10*b1 + a11*b0
    s12 := c12 + a0*b12 + a1*b11 + a2*b10 + a3*b9 + a4*b8 + a5*b7 + a6*b6 + a7*b5 + a8*b4 + a9*b3 + a10*b2 + a11*b1 + a12*b0
    s13 := c13 + a0*b13 + a1*b12 + a2*b11 + a3*b10 + a4*b9 + a5*b8 + a6*b7 + a7*b6 + a8*b5 + a9*b4 + a10*b3 + a11*b2 + a12*b1 + a13*b0
    s14 := c14 + a0*b14 + a1*b13 + a2*b12 + a3*b11 + a4*b10 + a5*b9 + a6*b8 + a7*b7 + a8*b6 + a9*b5 + a10*b4 + a11*b3 + a12*b2 + a13*b1 + a14*b0
    s15 := c15 + a0*b15 + a1*b14 + a2*b13 + a3*b12 + a4*b11 + a5*b10 + a6*b9 + a7*b8 + a8*b7 + a9*b6 + a10*b5 + a11*b4 + a12*b3 + a13*b2 + a14*b1 + a15*b0
    s16 := c16 + a0*b16 + a1*b15 + a2*b14 + a3*b13 + a4*b12 + a5*b11 + a6*b10 + a7*b9 + a8*b8 + a9*b7 + a10*b6 + a11*b5 + a12*b4 + a13*b3 + a14*b2 + a15*b1 + a16*b0
    s17 := c17 + a0*b17 + a1*b16 + a2*b15 + a3*b14 + a4*b13 + a5*b12 + a6*b11 + a7*b10 + a8*b9 + a9*b8 + a10*b7 + a11*b6 + a12*b5 + a13*b4 + a14*b3 + a15*b2 + a16*b1 + a17*b0
    s18 := c18 + a0*b18 + a1*b17 + a2*b16 + a3*b15 + a4*b14 + a5*b13 + a6*b12 + a7*b11 + a8*b10 + a9*b9 + a10*b8 + a11*b7 + a12*b6 + a13*b5 + a14*b4 + a15*b3 + a16*b2 + a17*b1 + a18*b0
    s19 := a1*b18 + a2*b17 + a3*b16 + a4*b15 + a5*b14 + a6*b13 + a7*b12 + a8*b11 + a9*b10 + a10*b9 + a11*b8 + a12*b7 + a13*b6 + a14*b5 + a15*b4 + a16*b3 + a17*b2 + a18*b1
    s20 := a2*b18 + a3*b17 + a4*b16 + a5*b15 + a6*b14 + a7*b13 + a8*b12 + a9*b11 + a10*b10 + a11*b9 + a12*b8 + a13*b7 + a14*b6 + a15*b5 + a16*b4 + a17*b3 + a18*b2
    s21 := a3*b18 + a4*b17 + a5*b16 + a6*b15 + a7*b14 + a8*b13 + a9*b12 + a10*b11 + a11*b10 + a12*b9 + a13*b8 + a14*b7 + a15*b6 + a16*b5 + a17*b4 + a18*b3
    s22 := a4*b18 + a5*b17 + a6*b16 + a7*b15 + a8*b14 + a9*b13 + a10*b12 + a11*b11 + a12*b10 + a13*b9 + a14*b8 + a15*b7 + a16*b6 + a17*b5 + a18*b4
    s23 := a5*b18 + a6*b17 + a7*b16 + a8*b15 + a9*b14 + a10*b13 + a11*b12 + a12*b11 + a13*b10 + a14*b9 + a15*b8 + a16*b7 + a17*b6 + a18*b5
    s24 := a6*b18 + a7*b17 + a8*b16 + a9*b15 + a10*b14 + a11*b13 + a12*b12 + a13*b11 + a14*b10 + a15*b9 + a16*b8 + a17*b7 + a18*b6
    s25 := a7*b18 + a8*b17 + a9*b16 + a10*b15 + a11*b14 + a12*b13 + a13*b12 + a14*b11 + a15*b10 + a16*b9 + a17*b8 + a18*b7
    s26 := a8*b18 + a9*b17 + a10*b16 + a11*b15 + a12*b14 + a13*b13 + a14*b12 + a15*b11 + a16*b10 + a17*b9 + a18*b8
    s27 := a9*b18 + a10*b17 + a11*b16 + a12*b15 + a13*b14 + a14*b13 + a15*b12 + a16*b11 + a17*b10 + a18*b9
    s28 := a10*b18 + a11*b17 + a12*b16 + a13*b15 + a14*b14 + a15*b13 + a16*b12 + a17*b11 + a18*b10
    s29 := a11*b18 + a12*b17 + a13*b16 + a14*b15 + a15*b14 + a16*b13 + a17*b12 + a18*b11
    s30 := a12*b18 + a13*b17 + a14*b16 + a15*b15 + a16*b14 + a17*b13 + a18*b12
    s31 := a13*b18 + a14*b17 + a15*b16 + a16*b15 + a17*b14 + a18*b13
    s32 := a14*b18 + a15*b17 + a16*b16 + a17*b15 + a18*b14
    s33 := a15*b18 + a16*b17 + a17*b16 + a18*b15
    s34 := a16*b18 + a17*b17 + a18*b16
    s35 := a17*b18 + a18*b17
    s36 := a18 * b18
    s37 := int64(0)

    // carry propagate
    c0 = s0 >> 24
    s0 -= c0 << 24
    s1 += c0
    c2 = s2 >> 24
    s2 -= c2 << 24
    s3 += c2
    c4 = s4 >> 24
    s4 -= c4 << 24
    s5 += c4
    c6 = s6 >> 24
    s6 -= c6 << 24
    s7 += c6
    c8 = s8 >> 24
    s8 -= c8 << 24
    s9 += c8
    c10 = s10 >> 24
    s10 -= c10 << 24
    s11 += c10
    c12 = s12 >> 24
    s12 -= c12 << 24
    s13 += c12
    c14 = s14 >> 24
    s14 -= c14 << 24
    s15 += c14
    c16 = s16 >> 24
    s16 -= c16 << 24
    s17 += c16
    c18 = s18 >> 24
    s18 -= c18 << 24
    s19 += c18
    c18 = s18 >> 24
    s18 -= c18 << 24
    s19 += c18
    c20 = s20 >> 24
    s20 -= c20 << 24
    s21 += c20
    c22 = s22 >> 24
    s22 -= c22 << 24
    s23 += c22
    c24 = s24 >> 24
    s24 -= c24 << 24
    s25 += c24
    c26 = s26 >> 24
    s26 -= c26 << 24
    s27 += c26
    c28 = s28 >> 24
    s28 -= c28 << 24
    s29 += c28
    c30 = s30 >> 24
    s30 -= c30 << 24
    s31 += c30
    c32 = s32 >> 24
    s32 -= c32 << 24
    s33 += c32
    c34 = s34 >> 24
    s34 -= c34 << 24
    s35 += c34
    c36 = s36 >> 24
    s36 -= c36 << 24
    s37 += c36

    c1 = s1 >> 24
    s1 -= c1 << 24
    s2 += c1
    c3 = s3 >> 24
    s3 -= c3 << 24
    s4 += c3
    c5 = s5 >> 24
    s5 -= c5 << 24
    s6 += c5
    c7 = s7 >> 24
    s7 -= c7 << 24
    s8 += c7
    c9 = s9 >> 24
    s9 -= c9 << 24
    s10 += c9
    c11 = s11 >> 24
    s11 -= c11 << 24
    s12 += c11
    c13 = s13 >> 24
    s13 -= c13 << 24
    s14 += c13
    c15 = s15 >> 24
    s15 -= c15 << 24
    s16 += c15
    c17 = s17 >> 24
    s17 -= c17 << 24
    s18 += c17
    c9 = s9 >> 24
    s9 -= c9 << 24
    s10 += c9
    c11 = s11 >> 24
    s11 -= c11 << 24
    s12 += c11
    c13 = s13 >> 24
    s13 -= c13 << 24
    s14 += c13
    c15 = s15 >> 24
    s15 -= c15 << 24
    s16 += c15
    c17 = s17 >> 24
    s17 -= c17 << 24
    s18 += c17
    c19 = s19 >> 24
    s19 -= c19 << 24
    s20 += c19
    c21 = s21 >> 24
    s21 -= c21 << 24
    s22 += c21
    c23 = s23 >> 24
    s23 -= c23 << 24
    s24 += c23
    c25 = s25 >> 24
    s25 -= c25 << 24
    s26 += c25
    c27 = s27 >> 24
    s27 -= c27 << 24
    s28 += c27
    c29 = s29 >> 24
    s29 -= c29 << 24
    s30 += c29
    c31 = s31 >> 24
    s31 -= c31 << 24
    s32 += c31
    c33 = s33 >> 24
    s33 -= c33 << 24
    s34 += c33
    c35 = s35 >> 24
    s35 -= c35 << 24
    s36 += c35

    s18 -= s37 * 0x13cc00
    s19 -= s37 * 0x4aad61
    s20 += s37 * 0x721cf6
    s21 -= s37 * 0x163d55
    s22 -= s37 * 0x09ca37
    s23 -= s37 * 0x4085b3
    s24 += s37 * 0x44a726
    s25 -= s37 * 0x3b6d27
    s26 += s37 * 0x7058ef
    s27 += s37 * 0x020cd7

    s17 -= s36 * 0x13cc00
    s18 -= s36 * 0x4aad61
    s19 += s36 * 0x721cf6
    s20 -= s36 * 0x163d55
    s21 -= s36 * 0x09ca37
    s22 -= s36 * 0x4085b3
    s23 += s36 * 0x44a726
    s24 -= s36 * 0x3b6d27
    s25 += s36 * 0x7058ef
    s26 += s36 * 0x020cd7

    s16 -= s35 * 0x13cc00
    s17 -= s35 * 0x4aad61
    s18 += s35 * 0x721cf6
    s19 -= s35 * 0x163d55
    s20 -= s35 * 0x09ca37
    s21 -= s35 * 0x4085b3
    s22 += s35 * 0x44a726
    s23 -= s35 * 0x3b6d27
    s24 += s35 * 0x7058ef
    s25 += s35 * 0x020cd7

    s15 -= s34 * 0x13cc00
    s16 -= s34 * 0x4aad61
    s17 += s34 * 0x721cf6
    s18 -= s34 * 0x163d55
    s19 -= s34 * 0x09ca37
    s20 -= s34 * 0x4085b3
    s21 += s34 * 0x44a726
    s22 -= s34 * 0x3b6d27
    s23 += s34 * 0x7058ef
    s24 += s34 * 0x020cd7

    s14 -= s33 * 0x13cc00
    s15 -= s33 * 0x4aad61
    s16 += s33 * 0x721cf6
    s17 -= s33 * 0x163d55
    s18 -= s33 * 0x09ca37
    s19 -= s33 * 0x4085b3
    s20 += s33 * 0x44a726
    s21 -= s33 * 0x3b6d27
    s22 += s33 * 0x7058ef
    s23 += s33 * 0x020cd7

    s13 -= s32 * 0x13cc00
    s14 -= s32 * 0x4aad61
    s15 += s32 * 0x721cf6
    s16 -= s32 * 0x163d55
    s17 -= s32 * 0x09ca37
    s18 -= s32 * 0x4085b3
    s19 += s32 * 0x44a726
    s20 -= s32 * 0x3b6d27
    s21 += s32 * 0x7058ef
    s22 += s32 * 0x020cd7

    s12 -= s31 * 0x13cc00
    s13 -= s31 * 0x4aad61
    s14 += s31 * 0x721cf6
    s15 -= s31 * 0x163d55
    s16 -= s31 * 0x09ca37
    s17 -= s31 * 0x4085b3
    s18 += s31 * 0x44a726
    s19 -= s31 * 0x3b6d27
    s20 += s31 * 0x7058ef
    s21 += s31 * 0x020cd7

    s11 -= s30 * 0x13cc00
    s12 -= s30 * 0x4aad61
    s13 += s30 * 0x721cf6
    s14 -= s30 * 0x163d55
    s15 -= s30 * 0x09ca37
    s16 -= s30 * 0x4085b3
    s17 += s30 * 0x44a726
    s18 -= s30 * 0x3b6d27
    s19 += s30 * 0x7058ef
    s20 += s30 * 0x020cd7

    s10 -= s29 * 0x13cc00
    s11 -= s29 * 0x4aad61
    s12 += s29 * 0x721cf6
    s13 -= s29 * 0x163d55
    s14 -= s29 * 0x09ca37
    s15 -= s29 * 0x4085b3
    s16 += s29 * 0x44a726
    s17 -= s29 * 0x3b6d27
    s18 += s29 * 0x7058ef
    s19 += s29 * 0x020cd7

    s9 -= s28 * 0x13cc00
    s10 -= s28 * 0x4aad61
    s11 += s28 * 0x721cf6
    s12 -= s28 * 0x163d55
    s13 -= s28 * 0x09ca37
    s14 -= s28 * 0x4085b3
    s15 += s28 * 0x44a726
    s16 -= s28 * 0x3b6d27
    s17 += s28 * 0x7058ef
    s18 += s28 * 0x020cd7
    s28 = 0

    // propagate carry here to avoid overflow
    // carry from even field elements
    // s0, s1, ..., s8 are up to 255, we don't need to calculate carries.
    c10 = s10 >> 24
    s10 -= c10 << 24
    s11 += c10
    c12 = s12 >> 24
    s12 -= c12 << 24
    s13 += c12
    c14 = s14 >> 24
    s14 -= c14 << 24
    s15 += c14
    c16 = s16 >> 24
    s16 -= c16 << 24
    s17 += c16
    c18 = s18 >> 24
    s18 -= c18 << 24
    s19 += c18
    c20 = s20 >> 24
    s20 -= c20 << 24
    s21 += c20
    c22 = s22 >> 24
    s22 -= c22 << 24
    s23 += c22
    c24 = s24 >> 24
    s24 -= c24 << 24
    s25 += c24
    c26 = s26 >> 24
    s26 -= c26 << 24
    s27 += c26

    // carry from odd field elements
    // s0, s1, ..., s8 are up to 255, we don't need to calculate carries.
    c9 = s9 >> 24
    s9 -= c9 << 24
    s10 += c9
    c11 = s11 >> 24
    s11 -= c11 << 24
    s12 += c11
    c13 = s13 >> 24
    s13 -= c13 << 24
    s14 += c13
    c15 = s15 >> 24
    s15 -= c15 << 24
    s16 += c15
    c17 = s17 >> 24
    s17 -= c17 << 24
    s18 += c17
    c19 = s19 >> 24
    s19 -= c19 << 24
    s20 += c19
    c21 = s21 >> 24
    s21 -= c21 << 24
    s22 += c21
    c23 = s23 >> 24
    s23 -= c23 << 24
    s24 += c23
    c25 = s25 >> 24
    s25 -= c25 << 24
    s26 += c25
    c27 = s27 >> 24
    s27 -= c27 << 24
    s28 += c27

    s9 -= s28 * 0x13cc00
    s10 -= s28 * 0x4aad61
    s11 += s28 * 0x721cf6
    s12 -= s28 * 0x163d55
    s13 -= s28 * 0x09ca37
    s14 -= s28 * 0x4085b3
    s15 += s28 * 0x44a726
    s16 -= s28 * 0x3b6d27
    s17 += s28 * 0x7058ef
    s18 += s28 * 0x020cd7

    s8 -= s27 * 0x13cc00
    s9 -= s27 * 0x4aad61
    s10 += s27 * 0x721cf6
    s11 -= s27 * 0x163d55
    s12 -= s27 * 0x09ca37
    s13 -= s27 * 0x4085b3
    s14 += s27 * 0x44a726
    s15 -= s27 * 0x3b6d27
    s16 += s27 * 0x7058ef
    s17 += s27 * 0x020cd7

    s7 -= s26 * 0x13cc00
    s8 -= s26 * 0x4aad61
    s9 += s26 * 0x721cf6
    s10 -= s26 * 0x163d55
    s11 -= s26 * 0x09ca37
    s12 -= s26 * 0x4085b3
    s13 += s26 * 0x44a726
    s14 -= s26 * 0x3b6d27
    s15 += s26 * 0x7058ef
    s16 += s26 * 0x020cd7

    s6 -= s25 * 0x13cc00
    s7 -= s25 * 0x4aad61
    s8 += s25 * 0x721cf6
    s9 -= s25 * 0x163d55
    s10 -= s25 * 0x09ca37
    s11 -= s25 * 0x4085b3
    s12 += s25 * 0x44a726
    s13 -= s25 * 0x3b6d27
    s14 += s25 * 0x7058ef
    s15 += s25 * 0x020cd7

    s5 -= s24 * 0x13cc00
    s6 -= s24 * 0x4aad61
    s7 += s24 * 0x721cf6
    s8 -= s24 * 0x163d55
    s9 -= s24 * 0x09ca37
    s10 -= s24 * 0x4085b3
    s11 += s24 * 0x44a726
    s12 -= s24 * 0x3b6d27
    s13 += s24 * 0x7058ef
    s14 += s24 * 0x020cd7

    s4 -= s23 * 0x13cc00
    s5 -= s23 * 0x4aad61
    s6 += s23 * 0x721cf6
    s7 -= s23 * 0x163d55
    s8 -= s23 * 0x09ca37
    s9 -= s23 * 0x4085b3
    s10 += s23 * 0x44a726
    s11 -= s23 * 0x3b6d27
    s12 += s23 * 0x7058ef
    s13 += s23 * 0x020cd7

    s3 -= s22 * 0x13cc00
    s4 -= s22 * 0x4aad61
    s5 += s22 * 0x721cf6
    s6 -= s22 * 0x163d55
    s7 -= s22 * 0x09ca37
    s8 -= s22 * 0x4085b3
    s9 += s22 * 0x44a726
    s10 -= s22 * 0x3b6d27
    s11 += s22 * 0x7058ef
    s12 += s22 * 0x020cd7

    s2 -= s21 * 0x13cc00
    s3 -= s21 * 0x4aad61
    s4 += s21 * 0x721cf6
    s5 -= s21 * 0x163d55
    s6 -= s21 * 0x09ca37
    s7 -= s21 * 0x4085b3
    s8 += s21 * 0x44a726
    s9 -= s21 * 0x3b6d27
    s10 += s21 * 0x7058ef
    s11 += s21 * 0x020cd7

    s1 -= s20 * 0x13cc00
    s2 -= s20 * 0x4aad61
    s3 += s20 * 0x721cf6
    s4 -= s20 * 0x163d55
    s5 -= s20 * 0x09ca37
    s6 -= s20 * 0x4085b3
    s7 += s20 * 0x44a726
    s8 -= s20 * 0x3b6d27
    s9 += s20 * 0x7058ef
    s10 += s20 * 0x020cd7

    s0 -= s19 * 0x13cc00
    s1 -= s19 * 0x4aad61
    s2 += s19 * 0x721cf6
    s3 -= s19 * 0x163d55
    s4 -= s19 * 0x09ca37
    s5 -= s19 * 0x4085b3
    s6 += s19 * 0x44a726
    s7 -= s19 * 0x3b6d27
    s8 += s19 * 0x7058ef
    s9 += s19 * 0x020cd7

    c18 = s18 >> 14
    s18 -= c18 << 14
    s0 -= c18 * 0x5844f3
    s1 += c18 * 0x3d6d55
    s2 -= c18 * 0x552379
    s3 += c18 * 0x723a71
    s4 -= c18 * 0x6cc273
    s5 -= c18 * 0x369021
    s6 -= c18 * 0x49aed6
    s7 += c18 * 0x3bb125
    s8 += c18 * 0x35dc16
    s9 += c18 * 0x000083

    // carry propagate
    c0 = s0 >> 24
    s0 -= c0 << 24
    s1 += c0
    c2 = s2 >> 24
    s2 -= c2 << 24
    s3 += c2
    c4 = s4 >> 24
    s4 -= c4 << 24
    s5 += c4
    c6 = s6 >> 24
    s6 -= c6 << 24
    s7 += c6
    c8 = s8 >> 24
    s8 -= c8 << 24
    s9 += c8
    c10 = s10 >> 24
    s10 -= c10 << 24
    s11 += c10
    c12 = s12 >> 24
    s12 -= c12 << 24
    s13 += c12
    c14 = s14 >> 24
    s14 -= c14 << 24
    s15 += c14
    c16 = s16 >> 24
    s16 -= c16 << 24
    s17 += c16

    c1 = s1 >> 24
    s1 -= c1 << 24
    s2 += c1
    c3 = s3 >> 24
    s3 -= c3 << 24
    s4 += c3
    c5 = s5 >> 24
    s5 -= c5 << 24
    s6 += c5
    c7 = s7 >> 24
    s7 -= c7 << 24
    s8 += c7
    c9 = s9 >> 24
    s9 -= c9 << 24
    s10 += c9
    c11 = s11 >> 24
    s11 -= c11 << 24
    s12 += c11
    c13 = s13 >> 24
    s13 -= c13 << 24
    s14 += c13
    c15 = s15 >> 24
    s15 -= c15 << 24
    s16 += c15
    c17 = s17 >> 24
    s17 -= c17 << 24
    s18 += c17

    c18 = s18 >> 14
    s18 -= c18 << 14
    s0 -= c18 * 0x5844f3
    s1 += c18 * 0x3d6d55
    s2 -= c18 * 0x552379
    s3 += c18 * 0x723a71
    s4 -= c18 * 0x6cc273
    s5 -= c18 * 0x369021
    s6 -= c18 * 0x49aed6
    s7 += c18 * 0x3bb125
    s8 += c18 * 0x35dc16
    s9 += c18 * 0x000083

    c0 = s0 >> 24
    s0 -= c0 << 24
    s1 += c0
    c1 = s1 >> 24
    s1 -= c1 << 24
    s2 += c1
    c2 = s2 >> 24
    s2 -= c2 << 24
    s3 += c2
    c3 = s3 >> 24
    s3 -= c3 << 24
    s4 += c3
    c4 = s4 >> 24
    s4 -= c4 << 24
    s5 += c4
    c5 = s5 >> 24
    s5 -= c5 << 24
    s6 += c5
    c6 = s6 >> 24
    s6 -= c6 << 24
    s7 += c6
    c7 = s7 >> 24
    s7 -= c7 << 24
    s8 += c7
    c8 = s8 >> 24
    s8 -= c8 << 24
    s9 += c8
    c9 = s9 >> 24
    s9 -= c9 << 24
    s10 += c9
    c10 = s10 >> 24
    s10 -= c10 << 24
    s11 += c10
    c11 = s11 >> 24
    s11 -= c11 << 24
    s12 += c11
    c12 = s12 >> 24
    s12 -= c12 << 24
    s13 += c12
    c13 = s13 >> 24
    s13 -= c13 << 24
    s14 += c13
    c14 = s14 >> 24
    s14 -= c14 << 24
    s15 += c14
    c15 = s15 >> 24
    s15 -= c15 << 24
    s16 += c15
    c16 = s16 >> 24
    s16 -= c16 << 24
    s17 += c16
    c17 = s17 >> 24
    s17 -= c17 << 24
    s18 += c17

    c18 = s18 >> 14
    s18 -= c18 << 14
    s0 -= c18 * 0x5844f3
    s1 += c18 * 0x3d6d55
    s2 -= c18 * 0x552379
    s3 += c18 * 0x723a71
    s4 -= c18 * 0x6cc273
    s5 -= c18 * 0x369021
    s6 -= c18 * 0x49aed6
    s7 += c18 * 0x3bb125
    s8 += c18 * 0x35dc16
    s9 += c18 * 0x000083

    c0 = s0 >> 24
    s0 -= c0 << 24
    s1 += c0
    c1 = s1 >> 24
    s1 -= c1 << 24
    s2 += c1
    c2 = s2 >> 24
    s2 -= c2 << 24
    s3 += c2
    c3 = s3 >> 24
    s3 -= c3 << 24
    s4 += c3
    c4 = s4 >> 24
    s4 -= c4 << 24
    s5 += c4
    c5 = s5 >> 24
    s5 -= c5 << 24
    s6 += c5
    c6 = s6 >> 24
    s6 -= c6 << 24
    s7 += c6
    c7 = s7 >> 24
    s7 -= c7 << 24
    s8 += c7
    c8 = s8 >> 24
    s8 -= c8 << 24
    s9 += c8
    c9 = s9 >> 24
    s9 -= c9 << 24
    s10 += c9
    c10 = s10 >> 24
    s10 -= c10 << 24
    s11 += c10
    c11 = s11 >> 24
    s11 -= c11 << 24
    s12 += c11
    c12 = s12 >> 24
    s12 -= c12 << 24
    s13 += c12
    c13 = s13 >> 24
    s13 -= c13 << 24
    s14 += c13
    c14 = s14 >> 24
    s14 -= c14 << 24
    s15 += c14
    c15 = s15 >> 24
    s15 -= c15 << 24
    s16 += c15
    c16 = s16 >> 24
    s16 -= c16 << 24
    s17 += c16
    c17 = s17 >> 24
    s17 -= c17 << 24
    s18 += c17

    // reduce
    d := (s0 - 0x5844f3) >> 24
    d = (s1 + 0x3d6d55 + d) >> 24
    d = (s2 - 0x552379 + d) >> 24
    d = (s3 + 0x723a71 + d) >> 24
    d = (s4 - 0x6cc273 + d) >> 24
    d = (s5 - 0x369021 + d) >> 24
    d = (s6 - 0x49aed6 + d) >> 24
    d = (s7 + 0x3bb125 + d) >> 24
    d = (s8 + 0x35dc16 + d) >> 24
    d = (s9 + 0x000083 + d) >> 24
    d = (s10 + d) >> 24
    d = (s11 + d) >> 24
    d = (s12 + d) >> 24
    d = (s13 + d) >> 24
    d = (s14 + d) >> 24
    d = (s15 + d) >> 24
    d = (s16 + d) >> 24
    d = (s17 + d) >> 24
    d = (s18 + d) >> 14

    // If s < l and d = 0, this will be a no-op. Otherwise, it's
    // effectively applying the reduction identity to the carry.
    s0 += d * 0xa7bb0d
    c0 = s0 >> 24
    s0 -= c0 << 24
    s1 += d*0x3d6d54 + c0
    c1 = s1 >> 24
    s1 -= c1 << 24
    s2 += d*0xaadc87 + c1
    c2 = s2 >> 24
    s2 -= c2 << 24
    s3 += d*0x723a70 + c2
    c3 = s3 >> 24
    s3 -= c3 << 24
    s4 += d*0x933d8d + c3
    c4 = s4 >> 24
    s4 -= c4 << 24
    s5 += d*0xc96fde + c4
    c5 = s5 >> 24
    s5 -= c5 << 24
    s6 += d*0xb65129 + c5
    c6 = s6 >> 24
    s6 -= c6 << 24
    s7 += d*0x3bb124 + c6
    c7 = s7 >> 24
    s7 -= c7 << 24
    s8 += d*0x35dc16 + c7
    c8 = s8 >> 24
    s8 -= c8 << 24
    s9 += d*0x000083 + c8
    c9 = s9 >> 24
    s9 -= c9 << 24
    s10 += c9
    c10 = s10 >> 24
    s10 -= c10 << 24
    s11 += c10
    c11 = s11 >> 24
    s11 -= c11 << 24
    s12 += c11
    c12 = s12 >> 24
    s12 -= c12 << 24
    s13 += c12
    c13 = s13 >> 24
    s13 -= c13 << 24
    s14 += c13
    c14 = s14 >> 24
    s14 -= c14 << 24
    s15 += c14
    c15 = s15 >> 24
    s15 -= c15 << 24
    s16 += c15
    c16 = s16 >> 24
    s16 -= c16 << 24
    s17 += c16
    c17 = s17 >> 24
    s17 -= c17 << 24
    s18 += c17
    c18 = s18 >> 14
    s18 -= c18 << 14

    // [print("out[%d] = byte(s%d >> %d)" % (i, i//3, (i%3)*8)) for i in range(56)]
    s[0] = byte(s0 >> 0)
    s[1] = byte(s0 >> 8)
    s[2] = byte(s0 >> 16)
    s[3] = byte(s1 >> 0)
    s[4] = byte(s1 >> 8)
    s[5] = byte(s1 >> 16)
    s[6] = byte(s2 >> 0)
    s[7] = byte(s2 >> 8)
    s[8] = byte(s2 >> 16)
    s[9] = byte(s3 >> 0)
    s[10] = byte(s3 >> 8)
    s[11] = byte(s3 >> 16)
    s[12] = byte(s4 >> 0)
    s[13] = byte(s4 >> 8)
    s[14] = byte(s4 >> 16)
    s[15] = byte(s5 >> 0)
    s[16] = byte(s5 >> 8)
    s[17] = byte(s5 >> 16)
    s[18] = byte(s6 >> 0)
    s[19] = byte(s6 >> 8)
    s[20] = byte(s6 >> 16)
    s[21] = byte(s7 >> 0)
    s[22] = byte(s7 >> 8)
    s[23] = byte(s7 >> 16)
    s[24] = byte(s8 >> 0)
    s[25] = byte(s8 >> 8)
    s[26] = byte(s8 >> 16)
    s[27] = byte(s9 >> 0)
    s[28] = byte(s9 >> 8)
    s[29] = byte(s9 >> 16)
    s[30] = byte(s10 >> 0)
    s[31] = byte(s10 >> 8)
    s[32] = byte(s10 >> 16)
    s[33] = byte(s11 >> 0)
    s[34] = byte(s11 >> 8)
    s[35] = byte(s11 >> 16)
    s[36] = byte(s12 >> 0)
    s[37] = byte(s12 >> 8)
    s[38] = byte(s12 >> 16)
    s[39] = byte(s13 >> 0)
    s[40] = byte(s13 >> 8)
    s[41] = byte(s13 >> 16)
    s[42] = byte(s14 >> 0)
    s[43] = byte(s14 >> 8)
    s[44] = byte(s14 >> 16)
    s[45] = byte(s15 >> 0)
    s[46] = byte(s15 >> 8)
    s[47] = byte(s15 >> 16)
    s[48] = byte(s16 >> 0)
    s[49] = byte(s16 >> 8)
    s[50] = byte(s16 >> 16)
    s[51] = byte(s17 >> 0)
    s[52] = byte(s17 >> 8)
    s[53] = byte(s17 >> 16)
    s[54] = byte(s18 >> 0)
    s[55] = byte(s18 >> 8)
}

// Input:
//
//	s[0]+256*s[1]+...+256^113*s[113] = s
//
// Output:
//
//	s[0]+256*s[1]+...+256^31*s[55] = s mod l
//	where l = 2^446 - 13818066809895115352007386748515426880336692474882178609894547503885.
func scReduce(out *[56]byte, s *[114]byte) {
    // [print("s%d := int64(s[%d]) | int64(s[%d])<<8 | int64(s[%d])<<16" % (i, i*3, i*3+1, i*3+2)) for i in range(38)]
    s0 := int64(s[0]) | int64(s[1])<<8 | int64(s[2])<<16
    s1 := int64(s[3]) | int64(s[4])<<8 | int64(s[5])<<16
    s2 := int64(s[6]) | int64(s[7])<<8 | int64(s[8])<<16
    s3 := int64(s[9]) | int64(s[10])<<8 | int64(s[11])<<16
    s4 := int64(s[12]) | int64(s[13])<<8 | int64(s[14])<<16
    s5 := int64(s[15]) | int64(s[16])<<8 | int64(s[17])<<16
    s6 := int64(s[18]) | int64(s[19])<<8 | int64(s[20])<<16
    s7 := int64(s[21]) | int64(s[22])<<8 | int64(s[23])<<16
    s8 := int64(s[24]) | int64(s[25])<<8 | int64(s[26])<<16
    s9 := int64(s[27]) | int64(s[28])<<8 | int64(s[29])<<16
    s10 := int64(s[30]) | int64(s[31])<<8 | int64(s[32])<<16
    s11 := int64(s[33]) | int64(s[34])<<8 | int64(s[35])<<16
    s12 := int64(s[36]) | int64(s[37])<<8 | int64(s[38])<<16
    s13 := int64(s[39]) | int64(s[40])<<8 | int64(s[41])<<16
    s14 := int64(s[42]) | int64(s[43])<<8 | int64(s[44])<<16
    s15 := int64(s[45]) | int64(s[46])<<8 | int64(s[47])<<16
    s16 := int64(s[48]) | int64(s[49])<<8 | int64(s[50])<<16
    s17 := int64(s[51]) | int64(s[52])<<8 | int64(s[53])<<16
    s18 := int64(s[54]) | int64(s[55])<<8 | int64(s[56])<<16
    s19 := int64(s[57]) | int64(s[58])<<8 | int64(s[59])<<16
    s20 := int64(s[60]) | int64(s[61])<<8 | int64(s[62])<<16
    s21 := int64(s[63]) | int64(s[64])<<8 | int64(s[65])<<16
    s22 := int64(s[66]) | int64(s[67])<<8 | int64(s[68])<<16
    s23 := int64(s[69]) | int64(s[70])<<8 | int64(s[71])<<16
    s24 := int64(s[72]) | int64(s[73])<<8 | int64(s[74])<<16
    s25 := int64(s[75]) | int64(s[76])<<8 | int64(s[77])<<16
    s26 := int64(s[78]) | int64(s[79])<<8 | int64(s[80])<<16
    s27 := int64(s[81]) | int64(s[82])<<8 | int64(s[83])<<16
    s28 := int64(s[84]) | int64(s[85])<<8 | int64(s[86])<<16
    s29 := int64(s[87]) | int64(s[88])<<8 | int64(s[89])<<16
    s30 := int64(s[90]) | int64(s[91])<<8 | int64(s[92])<<16
    s31 := int64(s[93]) | int64(s[94])<<8 | int64(s[95])<<16
    s32 := int64(s[96]) | int64(s[97])<<8 | int64(s[98])<<16
    s33 := int64(s[99]) | int64(s[100])<<8 | int64(s[101])<<16
    s34 := int64(s[102]) | int64(s[103])<<8 | int64(s[104])<<16
    s35 := int64(s[105]) | int64(s[106])<<8 | int64(s[107])<<16
    s36 := int64(s[108]) | int64(s[109])<<8 | int64(s[110])<<16
    s37 := int64(s[111]) | int64(s[112])<<8 | int64(s[113])<<16

    var c0, c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13, c14, c15, c16, c17, c18, c19 int64
    var c20, c21, c22, c23, c24, c25, c26, c27 int64

    s18 -= s37 * 0x13cc00
    s19 -= s37 * 0x4aad61
    s20 += s37 * 0x721cf6
    s21 -= s37 * 0x163d55
    s22 -= s37 * 0x09ca37
    s23 -= s37 * 0x4085b3
    s24 += s37 * 0x44a726
    s25 -= s37 * 0x3b6d27
    s26 += s37 * 0x7058ef
    s27 += s37 * 0x020cd7

    s17 -= s36 * 0x13cc00
    s18 -= s36 * 0x4aad61
    s19 += s36 * 0x721cf6
    s20 -= s36 * 0x163d55
    s21 -= s36 * 0x09ca37
    s22 -= s36 * 0x4085b3
    s23 += s36 * 0x44a726
    s24 -= s36 * 0x3b6d27
    s25 += s36 * 0x7058ef
    s26 += s36 * 0x020cd7

    s16 -= s35 * 0x13cc00
    s17 -= s35 * 0x4aad61
    s18 += s35 * 0x721cf6
    s19 -= s35 * 0x163d55
    s20 -= s35 * 0x09ca37
    s21 -= s35 * 0x4085b3
    s22 += s35 * 0x44a726
    s23 -= s35 * 0x3b6d27
    s24 += s35 * 0x7058ef
    s25 += s35 * 0x020cd7

    s15 -= s34 * 0x13cc00
    s16 -= s34 * 0x4aad61
    s17 += s34 * 0x721cf6
    s18 -= s34 * 0x163d55
    s19 -= s34 * 0x09ca37
    s20 -= s34 * 0x4085b3
    s21 += s34 * 0x44a726
    s22 -= s34 * 0x3b6d27
    s23 += s34 * 0x7058ef
    s24 += s34 * 0x020cd7

    s14 -= s33 * 0x13cc00
    s15 -= s33 * 0x4aad61
    s16 += s33 * 0x721cf6
    s17 -= s33 * 0x163d55
    s18 -= s33 * 0x09ca37
    s19 -= s33 * 0x4085b3
    s20 += s33 * 0x44a726
    s21 -= s33 * 0x3b6d27
    s22 += s33 * 0x7058ef
    s23 += s33 * 0x020cd7

    s13 -= s32 * 0x13cc00
    s14 -= s32 * 0x4aad61
    s15 += s32 * 0x721cf6
    s16 -= s32 * 0x163d55
    s17 -= s32 * 0x09ca37
    s18 -= s32 * 0x4085b3
    s19 += s32 * 0x44a726
    s20 -= s32 * 0x3b6d27
    s21 += s32 * 0x7058ef
    s22 += s32 * 0x020cd7

    s12 -= s31 * 0x13cc00
    s13 -= s31 * 0x4aad61
    s14 += s31 * 0x721cf6
    s15 -= s31 * 0x163d55
    s16 -= s31 * 0x09ca37
    s17 -= s31 * 0x4085b3
    s18 += s31 * 0x44a726
    s19 -= s31 * 0x3b6d27
    s20 += s31 * 0x7058ef
    s21 += s31 * 0x020cd7

    s11 -= s30 * 0x13cc00
    s12 -= s30 * 0x4aad61
    s13 += s30 * 0x721cf6
    s14 -= s30 * 0x163d55
    s15 -= s30 * 0x09ca37
    s16 -= s30 * 0x4085b3
    s17 += s30 * 0x44a726
    s18 -= s30 * 0x3b6d27
    s19 += s30 * 0x7058ef
    s20 += s30 * 0x020cd7

    s10 -= s29 * 0x13cc00
    s11 -= s29 * 0x4aad61
    s12 += s29 * 0x721cf6
    s13 -= s29 * 0x163d55
    s14 -= s29 * 0x09ca37
    s15 -= s29 * 0x4085b3
    s16 += s29 * 0x44a726
    s17 -= s29 * 0x3b6d27
    s18 += s29 * 0x7058ef
    s19 += s29 * 0x020cd7

    s9 -= s28 * 0x13cc00
    s10 -= s28 * 0x4aad61
    s11 += s28 * 0x721cf6
    s12 -= s28 * 0x163d55
    s13 -= s28 * 0x09ca37
    s14 -= s28 * 0x4085b3
    s15 += s28 * 0x44a726
    s16 -= s28 * 0x3b6d27
    s17 += s28 * 0x7058ef
    s18 += s28 * 0x020cd7
    s28 = 0

    // propagate carry here to avoid overflow
    // carry from even field elements
    // s0, s1, ..., s8 are up to 255, we don't need to calculate carries.
    c10 = s10 >> 24
    s10 -= c10 << 24
    s11 += c10
    c12 = s12 >> 24
    s12 -= c12 << 24
    s13 += c12
    c14 = s14 >> 24
    s14 -= c14 << 24
    s15 += c14
    c16 = s16 >> 24
    s16 -= c16 << 24
    s17 += c16
    c18 = s18 >> 24
    s18 -= c18 << 24
    s19 += c18
    c20 = s20 >> 24
    s20 -= c20 << 24
    s21 += c20
    c22 = s22 >> 24
    s22 -= c22 << 24
    s23 += c22
    c24 = s24 >> 24
    s24 -= c24 << 24
    s25 += c24
    c26 = s26 >> 24
    s26 -= c26 << 24
    s27 += c26

    // carry from odd field elements
    // s0, s1, ..., s8 are up to 255, we don't need to calculate carries.
    c9 = s9 >> 24
    s9 -= c9 << 24
    s10 += c9
    c11 = s11 >> 24
    s11 -= c11 << 24
    s12 += c11
    c13 = s13 >> 24
    s13 -= c13 << 24
    s14 += c13
    c15 = s15 >> 24
    s15 -= c15 << 24
    s16 += c15
    c17 = s17 >> 24
    s17 -= c17 << 24
    s18 += c17
    c19 = s19 >> 24
    s19 -= c19 << 24
    s20 += c19
    c21 = s21 >> 24
    s21 -= c21 << 24
    s22 += c21
    c23 = s23 >> 24
    s23 -= c23 << 24
    s24 += c23
    c25 = s25 >> 24
    s25 -= c25 << 24
    s26 += c25
    c27 = s27 >> 24
    s27 -= c27 << 24
    s28 += c27

    s9 -= s28 * 0x13cc00
    s10 -= s28 * 0x4aad61
    s11 += s28 * 0x721cf6
    s12 -= s28 * 0x163d55
    s13 -= s28 * 0x09ca37
    s14 -= s28 * 0x4085b3
    s15 += s28 * 0x44a726
    s16 -= s28 * 0x3b6d27
    s17 += s28 * 0x7058ef
    s18 += s28 * 0x020cd7

    s8 -= s27 * 0x13cc00
    s9 -= s27 * 0x4aad61
    s10 += s27 * 0x721cf6
    s11 -= s27 * 0x163d55
    s12 -= s27 * 0x09ca37
    s13 -= s27 * 0x4085b3
    s14 += s27 * 0x44a726
    s15 -= s27 * 0x3b6d27
    s16 += s27 * 0x7058ef
    s17 += s27 * 0x020cd7

    s7 -= s26 * 0x13cc00
    s8 -= s26 * 0x4aad61
    s9 += s26 * 0x721cf6
    s10 -= s26 * 0x163d55
    s11 -= s26 * 0x09ca37
    s12 -= s26 * 0x4085b3
    s13 += s26 * 0x44a726
    s14 -= s26 * 0x3b6d27
    s15 += s26 * 0x7058ef
    s16 += s26 * 0x020cd7

    s6 -= s25 * 0x13cc00
    s7 -= s25 * 0x4aad61
    s8 += s25 * 0x721cf6
    s9 -= s25 * 0x163d55
    s10 -= s25 * 0x09ca37
    s11 -= s25 * 0x4085b3
    s12 += s25 * 0x44a726
    s13 -= s25 * 0x3b6d27
    s14 += s25 * 0x7058ef
    s15 += s25 * 0x020cd7

    s5 -= s24 * 0x13cc00
    s6 -= s24 * 0x4aad61
    s7 += s24 * 0x721cf6
    s8 -= s24 * 0x163d55
    s9 -= s24 * 0x09ca37
    s10 -= s24 * 0x4085b3
    s11 += s24 * 0x44a726
    s12 -= s24 * 0x3b6d27
    s13 += s24 * 0x7058ef
    s14 += s24 * 0x020cd7

    s4 -= s23 * 0x13cc00
    s5 -= s23 * 0x4aad61
    s6 += s23 * 0x721cf6
    s7 -= s23 * 0x163d55
    s8 -= s23 * 0x09ca37
    s9 -= s23 * 0x4085b3
    s10 += s23 * 0x44a726
    s11 -= s23 * 0x3b6d27
    s12 += s23 * 0x7058ef
    s13 += s23 * 0x020cd7

    s3 -= s22 * 0x13cc00
    s4 -= s22 * 0x4aad61
    s5 += s22 * 0x721cf6
    s6 -= s22 * 0x163d55
    s7 -= s22 * 0x09ca37
    s8 -= s22 * 0x4085b3
    s9 += s22 * 0x44a726
    s10 -= s22 * 0x3b6d27
    s11 += s22 * 0x7058ef
    s12 += s22 * 0x020cd7

    s2 -= s21 * 0x13cc00
    s3 -= s21 * 0x4aad61
    s4 += s21 * 0x721cf6
    s5 -= s21 * 0x163d55
    s6 -= s21 * 0x09ca37
    s7 -= s21 * 0x4085b3
    s8 += s21 * 0x44a726
    s9 -= s21 * 0x3b6d27
    s10 += s21 * 0x7058ef
    s11 += s21 * 0x020cd7

    s1 -= s20 * 0x13cc00
    s2 -= s20 * 0x4aad61
    s3 += s20 * 0x721cf6
    s4 -= s20 * 0x163d55
    s5 -= s20 * 0x09ca37
    s6 -= s20 * 0x4085b3
    s7 += s20 * 0x44a726
    s8 -= s20 * 0x3b6d27
    s9 += s20 * 0x7058ef
    s10 += s20 * 0x020cd7

    s0 -= s19 * 0x13cc00
    s1 -= s19 * 0x4aad61
    s2 += s19 * 0x721cf6
    s3 -= s19 * 0x163d55
    s4 -= s19 * 0x09ca37
    s5 -= s19 * 0x4085b3
    s6 += s19 * 0x44a726
    s7 -= s19 * 0x3b6d27
    s8 += s19 * 0x7058ef
    s9 += s19 * 0x020cd7

    c := s18 >> 14
    s18 -= c << 14
    s0 -= c * 0x5844f3
    s1 += c * 0x3d6d55
    s2 -= c * 0x552379
    s3 += c * 0x723a71
    s4 -= c * 0x6cc273
    s5 -= c * 0x369021
    s6 -= c * 0x49aed6
    s7 += c * 0x3bb125
    s8 += c * 0x35dc16
    s9 += c * 0x000083

    // carry propagate
    c0 = s0 >> 24
    s0 -= c0 << 24
    s1 += c0
    c2 = s2 >> 24
    s2 -= c2 << 24
    s3 += c2
    c4 = s4 >> 24
    s4 -= c4 << 24
    s5 += c4
    c6 = s6 >> 24
    s6 -= c6 << 24
    s7 += c6
    c8 = s8 >> 24
    s8 -= c8 << 24
    s9 += c8
    c10 = s10 >> 24
    s10 -= c10 << 24
    s11 += c10
    c12 = s12 >> 24
    s12 -= c12 << 24
    s13 += c12
    c14 = s14 >> 24
    s14 -= c14 << 24
    s15 += c14
    c16 = s16 >> 24
    s16 -= c16 << 24
    s17 += c16

    c1 = s1 >> 24
    s1 -= c1 << 24
    s2 += c1
    c3 = s3 >> 24
    s3 -= c3 << 24
    s4 += c3
    c5 = s5 >> 24
    s5 -= c5 << 24
    s6 += c5
    c7 = s7 >> 24
    s7 -= c7 << 24
    s8 += c7
    c9 = s9 >> 24
    s9 -= c9 << 24
    s10 += c9
    c11 = s11 >> 24
    s11 -= c11 << 24
    s12 += c11
    c13 = s13 >> 24
    s13 -= c13 << 24
    s14 += c13
    c15 = s15 >> 24
    s15 -= c15 << 24
    s16 += c15
    c17 = s17 >> 24
    s17 -= c17 << 24
    s18 += c17

    c = s18 >> 14
    s18 -= c << 14
    s0 -= c * 0x5844f3
    s1 += c * 0x3d6d55
    s2 -= c * 0x552379
    s3 += c * 0x723a71
    s4 -= c * 0x6cc273
    s5 -= c * 0x369021
    s6 -= c * 0x49aed6
    s7 += c * 0x3bb125
    s8 += c * 0x35dc16
    s9 += c * 0x000083

    c0 = s0 >> 24
    s0 -= c0 << 24
    s1 += c0
    c1 = s1 >> 24
    s1 -= c1 << 24
    s2 += c1
    c2 = s2 >> 24
    s2 -= c2 << 24
    s3 += c2
    c3 = s3 >> 24
    s3 -= c3 << 24
    s4 += c3
    c4 = s4 >> 24
    s4 -= c4 << 24
    s5 += c4
    c5 = s5 >> 24
    s5 -= c5 << 24
    s6 += c5
    c6 = s6 >> 24
    s6 -= c6 << 24
    s7 += c6
    c7 = s7 >> 24
    s7 -= c7 << 24
    s8 += c7
    c8 = s8 >> 24
    s8 -= c8 << 24
    s9 += c8
    c9 = s9 >> 24
    s9 -= c9 << 24
    s10 += c9
    c10 = s10 >> 24
    s10 -= c10 << 24
    s11 += c10
    c11 = s11 >> 24
    s11 -= c11 << 24
    s12 += c11
    c12 = s12 >> 24
    s12 -= c12 << 24
    s13 += c12
    c13 = s13 >> 24
    s13 -= c13 << 24
    s14 += c13
    c14 = s14 >> 24
    s14 -= c14 << 24
    s15 += c14
    c15 = s15 >> 24
    s15 -= c15 << 24
    s16 += c15
    c16 = s16 >> 24
    s16 -= c16 << 24
    s17 += c16
    c17 = s17 >> 24
    s17 -= c17 << 24
    s18 += c17

    c = s18 >> 14
    s18 -= c << 14
    s0 -= c * 0x5844f3
    s1 += c * 0x3d6d55
    s2 -= c * 0x552379
    s3 += c * 0x723a71
    s4 -= c * 0x6cc273
    s5 -= c * 0x369021
    s6 -= c * 0x49aed6
    s7 += c * 0x3bb125
    s8 += c * 0x35dc16
    s9 += c * 0x000083

    c0 = s0 >> 24
    s0 -= c0 << 24
    s1 += c0
    c1 = s1 >> 24
    s1 -= c1 << 24
    s2 += c1
    c2 = s2 >> 24
    s2 -= c2 << 24
    s3 += c2
    c3 = s3 >> 24
    s3 -= c3 << 24
    s4 += c3
    c4 = s4 >> 24
    s4 -= c4 << 24
    s5 += c4
    c5 = s5 >> 24
    s5 -= c5 << 24
    s6 += c5
    c6 = s6 >> 24
    s6 -= c6 << 24
    s7 += c6
    c7 = s7 >> 24
    s7 -= c7 << 24
    s8 += c7
    c8 = s8 >> 24
    s8 -= c8 << 24
    s9 += c8
    c9 = s9 >> 24
    s9 -= c9 << 24
    s10 += c9
    c10 = s10 >> 24
    s10 -= c10 << 24
    s11 += c10
    c11 = s11 >> 24
    s11 -= c11 << 24
    s12 += c11
    c12 = s12 >> 24
    s12 -= c12 << 24
    s13 += c12
    c13 = s13 >> 24
    s13 -= c13 << 24
    s14 += c13
    c14 = s14 >> 24
    s14 -= c14 << 24
    s15 += c14
    c15 = s15 >> 24
    s15 -= c15 << 24
    s16 += c15
    c16 = s16 >> 24
    s16 -= c16 << 24
    s17 += c16
    c17 = s17 >> 24
    s17 -= c17 << 24
    s18 += c17

    // reduce
    d := (s0 - 0x5844f3) >> 24
    d = (s1 + 0x3d6d55 + d) >> 24
    d = (s2 - 0x552379 + d) >> 24
    d = (s3 + 0x723a71 + d) >> 24
    d = (s4 - 0x6cc273 + d) >> 24
    d = (s5 - 0x369021 + d) >> 24
    d = (s6 - 0x49aed6 + d) >> 24
    d = (s7 + 0x3bb125 + d) >> 24
    d = (s8 + 0x35dc16 + d) >> 24
    d = (s9 + 0x000083 + d) >> 24
    d = (s10 + d) >> 24
    d = (s11 + d) >> 24
    d = (s12 + d) >> 24
    d = (s13 + d) >> 24
    d = (s14 + d) >> 24
    d = (s15 + d) >> 24
    d = (s16 + d) >> 24
    d = (s17 + d) >> 24
    d = (s18 + d) >> 14

    // If s < l and d = 0, this will be a no-op. Otherwise, it's
    // effectively applying the reduction identity to the carry.
    s0 += d * 0xa7bb0d
    c = s0 >> 24
    s0 -= c << 24
    s1 += d*0x3d6d54 + c
    c = s1 >> 24
    s1 -= c << 24
    s2 += d*0xaadc87 + c
    c = s2 >> 24
    s2 -= c << 24
    s3 += d*0x723a70 + c
    c = s3 >> 24
    s3 -= c << 24
    s4 += d*0x933d8d + c
    c = s4 >> 24
    s4 -= c << 24
    s5 += d*0xc96fde + c
    c = s5 >> 24
    s5 -= c << 24
    s6 += d*0xb65129 + c
    c = s6 >> 24
    s6 -= c << 24
    s7 += d*0x3bb124 + c
    c = s7 >> 24
    s7 -= c << 24
    s8 += d*0x35dc16 + c
    c = s8 >> 24
    s8 -= c << 24
    s9 += d*0x000083 + c
    c = s9 >> 24
    s9 -= c << 24
    s10 += c
    c = s10 >> 24
    s10 -= c << 24
    s11 += c
    c = s11 >> 24
    s11 -= c << 24
    s12 += c
    c = s12 >> 24
    s12 -= c << 24
    s13 += c
    c = s13 >> 24
    s13 -= c << 24
    s14 += c
    c = s14 >> 24
    s14 -= c << 24
    s15 += c
    c = s15 >> 24
    s15 -= c << 24
    s16 += c
    c = s16 >> 24
    s16 -= c << 24
    s17 += c
    c = s17 >> 24
    s17 -= c << 24
    s18 += c
    c = s18 >> 14
    s18 -= c << 14

    // [print("out[%d] = byte(s%d >> %d)" % (i, i//3, (i%3)*8)) for i in range(56)]
    out[0] = byte(s0 >> 0)
    out[1] = byte(s0 >> 8)
    out[2] = byte(s0 >> 16)
    out[3] = byte(s1 >> 0)
    out[4] = byte(s1 >> 8)
    out[5] = byte(s1 >> 16)
    out[6] = byte(s2 >> 0)
    out[7] = byte(s2 >> 8)
    out[8] = byte(s2 >> 16)
    out[9] = byte(s3 >> 0)
    out[10] = byte(s3 >> 8)
    out[11] = byte(s3 >> 16)
    out[12] = byte(s4 >> 0)
    out[13] = byte(s4 >> 8)
    out[14] = byte(s4 >> 16)
    out[15] = byte(s5 >> 0)
    out[16] = byte(s5 >> 8)
    out[17] = byte(s5 >> 16)
    out[18] = byte(s6 >> 0)
    out[19] = byte(s6 >> 8)
    out[20] = byte(s6 >> 16)
    out[21] = byte(s7 >> 0)
    out[22] = byte(s7 >> 8)
    out[23] = byte(s7 >> 16)
    out[24] = byte(s8 >> 0)
    out[25] = byte(s8 >> 8)
    out[26] = byte(s8 >> 16)
    out[27] = byte(s9 >> 0)
    out[28] = byte(s9 >> 8)
    out[29] = byte(s9 >> 16)
    out[30] = byte(s10 >> 0)
    out[31] = byte(s10 >> 8)
    out[32] = byte(s10 >> 16)
    out[33] = byte(s11 >> 0)
    out[34] = byte(s11 >> 8)
    out[35] = byte(s11 >> 16)
    out[36] = byte(s12 >> 0)
    out[37] = byte(s12 >> 8)
    out[38] = byte(s12 >> 16)
    out[39] = byte(s13 >> 0)
    out[40] = byte(s13 >> 8)
    out[41] = byte(s13 >> 16)
    out[42] = byte(s14 >> 0)
    out[43] = byte(s14 >> 8)
    out[44] = byte(s14 >> 16)
    out[45] = byte(s15 >> 0)
    out[46] = byte(s15 >> 8)
    out[47] = byte(s15 >> 16)
    out[48] = byte(s16 >> 0)
    out[49] = byte(s16 >> 8)
    out[50] = byte(s16 >> 16)
    out[51] = byte(s17 >> 0)
    out[52] = byte(s17 >> 8)
    out[53] = byte(s17 >> 16)
    out[54] = byte(s18 >> 0)
    out[55] = byte(s18 >> 8)
}

func (s *Scalar) signedRadix16() [112]int8 {
    if s.s[55] >= 0x80 {
        panic("edwards448: scalar has high bit set illegally")
    }

    var digits [112]int8

    // Compute unsigned radix-16 digits:
    for i := 0; i < 56; i++ {
        digits[2*i] = int8(s.s[i] & 0xF)
        digits[2*i+1] = int8((s.s[i] >> 4) & 0xF)
    }

    // Recenter coefficients:
    for i := 0; i < 112-1; i++ {
        carry := (digits[i] + 8) >> 4
        digits[i] -= carry << 4
        digits[i+1] += carry
    }

    return digits
}

// nonAdjacentForm computes a width-w non-adjacent form for this scalar.
//
// w must be between 2 and 8, or nonAdjacentForm will panic.
func (s *Scalar) nonAdjacentForm(w uint) [448]int8 {
    // This implementation is adapted from the one
    // in curve25519-dalek and is documented there:
    // https://github.com/dalek-cryptography/curve25519-dalek/blob/f630041af28e9a405255f98a8a93adca18e4315b/src/scalar.rs#L800-L871
    if w < 2 {
        panic("w must be at least 2 by the definition of NAF")
    } else if w > 8 {
        panic("NAF digits must fit in int8")
    }

    width := uint64(1 << w)
    windowMask := uint64(width - 1)

    var naf [448]int8 // non adjacent form of s
    var digits [8]uint64

    for i := 0; i < 7; i++ {
        digits[i] = binary.LittleEndian.Uint64(s.s[i*8:])
    }

    pos := uint(0)
    carry := uint64(0)
    for pos < uint(len(naf)) {
        indexU64 := pos / 64
        indexBit := pos % 64
        var bitBuf uint64
        if indexBit < 64-w {
            // This window's bits are contained in a single u64
            bitBuf = digits[indexU64] >> indexBit
        } else {
            // Combine the current 64 bits with bits from the next 64
            bitBuf = (digits[indexU64] >> indexBit) | (digits[1+indexU64] << (64 - indexBit))
        }

        // Add carry into the current window
        window := carry + (bitBuf & windowMask)

        if window&1 == 0 {
            // If the window value is even, preserve the carry and continue.
            // Why is the carry preserved?
            // If carry == 0 and window & 1 == 0,
            //    then the next carry should be 0
            // If carry == 1 and window & 1 == 0,
            //    then bit_buf & 1 == 1 so the next carry should be 1
            pos += 1
            continue
        }

        if window < width/2 {
            carry = 0
            naf[pos] = int8(window)
        } else {
            carry = 1
            naf[pos] = int8(window) - int8(width)
        }

        pos += w
    }

    return naf
}
