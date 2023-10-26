// Package field implements fast arithmetic modulo 2^448-2^224-1.

// based on https://github.com/golang/crypto/blob/56aed061732aaf690a941aa617c5b0e322727650/curve25519/internal/field/fe.go
//
// original copyright:
// Copyright (c) 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package field

import "math/bits"

// Element represents an element of the field GF(2^448-2^224-1). Note that this
// is not a cryptographically secure group
//
// This type works similarly to math/big.Int, and all arguments and receivers
// are allowed to alias.
//
// The zero value is a valid zero element.
type Element struct {
    // An element t represents the integer
    //     t.l0 + t.l1*2^56 + t.l2*2^112 + t.l3*2^168 + t.l4*2^224
    //   + t.l5*2^280 + t.l6*2^336 + t.l7*2^392
    //
    // Between operations, all limbs are expected to be lower than 2^57.
    l0 uint64
    l1 uint64
    l2 uint64
    l3 uint64
    l4 uint64
    l5 uint64
    l6 uint64
    l7 uint64
}

const maskLow56Bits uint64 = (1 << 56) - 1

var feZero = &Element{0, 0, 0, 0, 0, 0, 0, 0}

// Zero sets v = 0, and returns v.
func (v *Element) Zero() *Element {
    *v = *feZero
    return v
}

var feOne = &Element{1, 0, 0, 0, 0, 0, 0, 0}

// One sets v = 1, and returns v.
func (v *Element) One() *Element {
    *v = *feOne
    return v
}

// IsNegative returns 1 if v is negative, and 0 otherwise.
func (v *Element) IsNegative() int {
    v0 := *v // shallow copy
    v0.reduce()
    return int(v0.l0 & 1)
}

func (v *Element) Abs(u *Element) *Element {
    var x Element
    x.Negate(u)
    return v.Select(&x, u, u.IsNegative())
}

// reduce reduces v modulo 2^448 - 2^224 - 1 and returns it.
func (v *Element) reduce() *Element {
    v.carryPropagate()

    // After the light reduction we now have a field element representation
    // v < 2^448 + 2^232 + 2^8, but need v < 2^448 - 2^224 - 1.

    // If v >= 2^448 - 2^224 - 1, then v + 2^224 + 1 >= 2^448, which would overflow 2^448 - 1,
    // generating a carry. That is, c will be 0 if v < 2^448 - 2^224 - 1, and 1 otherwise.
    c := (v.l0 + 1) >> 56
    c = (v.l1 + c) >> 56
    c = (v.l2 + c) >> 56
    c = (v.l3 + c) >> 56
    c = (v.l4 + c + 1) >> 56
    c = (v.l5 + c) >> 56
    c = (v.l6 + c) >> 56
    c = (v.l7 + c) >> 56

    // If v < 2^448 - 2^224 - 1 and c = 0, this will be a no-op. Otherwise, it's
    // effectively applying the reduction identity to the carry.
    v.l0 += c
    v.l4 += c

    v.l1 += v.l0 >> 56
    v.l0 &= maskLow56Bits
    v.l2 += v.l1 >> 56
    v.l1 &= maskLow56Bits
    v.l3 += v.l2 >> 56
    v.l2 &= maskLow56Bits
    v.l4 += v.l3 >> 56
    v.l3 &= maskLow56Bits
    v.l5 += v.l4 >> 56
    v.l4 &= maskLow56Bits
    v.l6 += v.l5 >> 56
    v.l5 &= maskLow56Bits
    v.l7 += v.l6 >> 56
    v.l6 &= maskLow56Bits
    // no additional carry
    v.l7 &= maskLow56Bits

    return v
}

// Add sets v = a + b, and returns v.
func (v *Element) Add(a, b *Element) *Element {
    v.l0 = a.l0 + b.l0
    v.l1 = a.l1 + b.l1
    v.l2 = a.l2 + b.l2
    v.l3 = a.l3 + b.l3
    v.l4 = a.l4 + b.l4
    v.l5 = a.l5 + b.l5
    v.l6 = a.l6 + b.l6
    v.l7 = a.l7 + b.l7

    // propagate carry
    c0 := v.l0 >> 56
    c1 := v.l1 >> 56
    c2 := v.l2 >> 56
    c3 := v.l3 >> 56
    c4 := v.l4 >> 56
    c5 := v.l5 >> 56
    c6 := v.l6 >> 56
    c7 := v.l7 >> 56

    // c7 is at most 64 - 56 = 8 bits,
    // so the final l0 will be at most 57 bits. Similarly for the rest.
    v.l0 = v.l0&maskLow56Bits + c7
    v.l1 = v.l1&maskLow56Bits + c0
    v.l2 = v.l2&maskLow56Bits + c1
    v.l3 = v.l3&maskLow56Bits + c2
    v.l4 = v.l4&maskLow56Bits + c3 + c7
    v.l5 = v.l5&maskLow56Bits + c4
    v.l6 = v.l6&maskLow56Bits + c5
    v.l7 = v.l7&maskLow56Bits + c6

    return v
}

// Subtract sets v = a - b, and returns v.
func (v *Element) Sub(a, b *Element) *Element {
    // We first add 2 * p, to guarantee the subtraction won't underflow, and
    // then subtract b (which can be up to 2^448 + 2^232 + 2^8).
    v.l0 = (a.l0 + 2*0xFF_FFFF_FFFF_FFFF) - b.l0
    v.l1 = (a.l1 + 2*0xFF_FFFF_FFFF_FFFF) - b.l1
    v.l2 = (a.l2 + 2*0xFF_FFFF_FFFF_FFFF) - b.l2
    v.l3 = (a.l3 + 2*0xFF_FFFF_FFFF_FFFF) - b.l3
    v.l4 = (a.l4 + 2*0xFF_FFFF_FFFF_FFFE) - b.l4
    v.l5 = (a.l5 + 2*0xFF_FFFF_FFFF_FFFF) - b.l5
    v.l6 = (a.l6 + 2*0xFF_FFFF_FFFF_FFFF) - b.l6
    v.l7 = (a.l7 + 2*0xFF_FFFF_FFFF_FFFF) - b.l7

    // propagate carry
    c0 := v.l0 >> 56
    c1 := v.l1 >> 56
    c2 := v.l2 >> 56
    c3 := v.l3 >> 56
    c4 := v.l4 >> 56
    c5 := v.l5 >> 56
    c6 := v.l6 >> 56
    c7 := v.l7 >> 56

    // c7 is at most 64 - 56 = 8 bits,
    // so the final l0 will be at most 57 bits. Similarly for the rest.
    v.l0 = v.l0&maskLow56Bits + c7
    v.l1 = v.l1&maskLow56Bits + c0
    v.l2 = v.l2&maskLow56Bits + c1
    v.l3 = v.l3&maskLow56Bits + c2
    v.l4 = v.l4&maskLow56Bits + c3 + c7
    v.l5 = v.l5&maskLow56Bits + c4
    v.l6 = v.l6&maskLow56Bits + c5
    v.l7 = v.l7&maskLow56Bits + c6

    return v
}

// Negate sets v = -a, and returns v.
func (v *Element) Negate(a *Element) *Element {
    // We first add 2 * p, to guarantee the subtraction won't underflow, and
    // then subtract b (which can be up to 2^448 + 2^232 + 2^8).
    v.l0 = 2*0xFF_FFFF_FFFF_FFFF - a.l0
    v.l1 = 2*0xFF_FFFF_FFFF_FFFF - a.l1
    v.l2 = 2*0xFF_FFFF_FFFF_FFFF - a.l2
    v.l3 = 2*0xFF_FFFF_FFFF_FFFF - a.l3
    v.l4 = 2*0xFF_FFFF_FFFF_FFFE - a.l4
    v.l5 = 2*0xFF_FFFF_FFFF_FFFF - a.l5
    v.l6 = 2*0xFF_FFFF_FFFF_FFFF - a.l6
    v.l7 = 2*0xFF_FFFF_FFFF_FFFF - a.l7

    // propagate carry
    c0 := v.l0 >> 56
    c1 := v.l1 >> 56
    c2 := v.l2 >> 56
    c3 := v.l3 >> 56
    c4 := v.l4 >> 56
    c5 := v.l5 >> 56
    c6 := v.l6 >> 56
    c7 := v.l7 >> 56

    // c7 is at most 64 - 56 = 8 bits,
    // so the final l0 will be at most 57 bits. Similarly for the rest.
    v.l0 = v.l0&maskLow56Bits + c7
    v.l1 = v.l1&maskLow56Bits + c0
    v.l2 = v.l2&maskLow56Bits + c1
    v.l3 = v.l3&maskLow56Bits + c2
    v.l4 = v.l4&maskLow56Bits + c3 + c7
    v.l5 = v.l5&maskLow56Bits + c4
    v.l6 = v.l6&maskLow56Bits + c5
    v.l7 = v.l7&maskLow56Bits + c6

    return v
}

// Set sets v = a, and returns v.
func (v *Element) Set(a *Element) *Element {
    *v = *a
    return v
}

// SetBytes sets v to x, which must be a 56-byte little-endian encoding.
func (v *Element) SetBytes(x []byte) *Element {
    if len(x) != 56 {
        panic("curve448: invalid field element input size")
    }
    _ = x[55] // bounds check hint to compiler; see golang.org/issue/14808
    v.l0 = uint64(x[0]) +
        uint64(x[1])<<8 +
        uint64(x[2])<<16 +
        uint64(x[3])<<24 +
        uint64(x[4])<<32 +
        uint64(x[5])<<40 +
        uint64(x[6])<<48

    v.l1 = uint64(x[7]) +
        uint64(x[8])<<8 +
        uint64(x[9])<<16 +
        uint64(x[10])<<24 +
        uint64(x[11])<<32 +
        uint64(x[12])<<40 +
        uint64(x[13])<<48

    v.l2 = uint64(x[14]) +
        uint64(x[15])<<8 +
        uint64(x[16])<<16 +
        uint64(x[17])<<24 +
        uint64(x[18])<<32 +
        uint64(x[19])<<40 +
        uint64(x[20])<<48

    v.l3 = uint64(x[21]) +
        uint64(x[22])<<8 +
        uint64(x[23])<<16 +
        uint64(x[24])<<24 +
        uint64(x[25])<<32 +
        uint64(x[26])<<40 +
        uint64(x[27])<<48

    v.l4 = uint64(x[28]) +
        uint64(x[29])<<8 +
        uint64(x[30])<<16 +
        uint64(x[31])<<24 +
        uint64(x[32])<<32 +
        uint64(x[33])<<40 +
        uint64(x[34])<<48

    v.l5 = uint64(x[35]) +
        uint64(x[36])<<8 +
        uint64(x[37])<<16 +
        uint64(x[38])<<24 +
        uint64(x[39])<<32 +
        uint64(x[40])<<40 +
        uint64(x[41])<<48

    v.l6 = uint64(x[42]) +
        uint64(x[43])<<8 +
        uint64(x[44])<<16 +
        uint64(x[45])<<24 +
        uint64(x[46])<<32 +
        uint64(x[47])<<40 +
        uint64(x[48])<<48

    v.l7 = uint64(x[49]) +
        uint64(x[50])<<8 +
        uint64(x[51])<<16 +
        uint64(x[52])<<24 +
        uint64(x[53])<<32 +
        uint64(x[54])<<40 +
        uint64(x[55])<<48

    return v
}

func (v *Element) Bytes() []byte {
    var out [56]byte
    return v.bytes(&out)
}

func (v *Element) bytes(out *[56]byte) []byte {
    t := *v
    t.reduce()
    out[0] = byte(t.l0)
    out[1] = byte(t.l0 >> 8)
    out[2] = byte(t.l0 >> 16)
    out[3] = byte(t.l0 >> 24)
    out[4] = byte(t.l0 >> 32)
    out[5] = byte(t.l0 >> 40)
    out[6] = byte(t.l0 >> 48)

    out[7] = byte(t.l1)
    out[8] = byte(t.l1 >> 8)
    out[9] = byte(t.l1 >> 16)
    out[10] = byte(t.l1 >> 24)
    out[11] = byte(t.l1 >> 32)
    out[12] = byte(t.l1 >> 40)
    out[13] = byte(t.l1 >> 48)

    out[14] = byte(t.l2)
    out[15] = byte(t.l2 >> 8)
    out[16] = byte(t.l2 >> 16)
    out[17] = byte(t.l2 >> 24)
    out[18] = byte(t.l2 >> 32)
    out[19] = byte(t.l2 >> 40)
    out[20] = byte(t.l2 >> 48)

    out[21] = byte(t.l3)
    out[22] = byte(t.l3 >> 8)
    out[23] = byte(t.l3 >> 16)
    out[24] = byte(t.l3 >> 24)
    out[25] = byte(t.l3 >> 32)
    out[26] = byte(t.l3 >> 40)
    out[27] = byte(t.l3 >> 48)

    out[28] = byte(t.l4)
    out[29] = byte(t.l4 >> 8)
    out[30] = byte(t.l4 >> 16)
    out[31] = byte(t.l4 >> 24)
    out[32] = byte(t.l4 >> 32)
    out[33] = byte(t.l4 >> 40)
    out[34] = byte(t.l4 >> 48)

    out[35] = byte(t.l5)
    out[36] = byte(t.l5 >> 8)
    out[37] = byte(t.l5 >> 16)
    out[38] = byte(t.l5 >> 24)
    out[39] = byte(t.l5 >> 32)
    out[40] = byte(t.l5 >> 40)
    out[41] = byte(t.l5 >> 48)

    out[42] = byte(t.l6)
    out[43] = byte(t.l6 >> 8)
    out[44] = byte(t.l6 >> 16)
    out[45] = byte(t.l6 >> 24)
    out[46] = byte(t.l6 >> 32)
    out[47] = byte(t.l6 >> 40)
    out[48] = byte(t.l6 >> 48)

    out[49] = byte(t.l7)
    out[50] = byte(t.l7 >> 8)
    out[51] = byte(t.l7 >> 16)
    out[52] = byte(t.l7 >> 24)
    out[53] = byte(t.l7 >> 32)
    out[54] = byte(t.l7 >> 40)
    out[55] = byte(t.l7 >> 48)
    return out[:]
}

// Equal returns 1 if v and u are equal, and 0 otherwise.
func (v *Element) Equal(u *Element) int {
    u0 := *u // shallow copy
    v0 := *v // shallow copy
    u0.reduce()
    v0.reduce()

    c := v0.l0 ^ u0.l0
    c |= v0.l1 ^ u0.l1
    c |= v0.l2 ^ u0.l2
    c |= v0.l3 ^ u0.l3
    c |= v0.l4 ^ u0.l4
    c |= v0.l5 ^ u0.l5
    c |= v0.l6 ^ u0.l6
    c |= v0.l7 ^ u0.l7
    c = (c & 0xFFFFFFFF) | (c >> 32)
    c--
    return int(c >> 63)
}

// mask64Bits returns 0xffffffff if cond is 1, and 0 otherwise.
func mask64Bits(cond int) uint64 { return uint64(0) - uint64(cond) }

// Select sets v to a if cond == 1, and to b if cond == 0.
func (v *Element) Select(a, b *Element, cond int) *Element {
    m := mask64Bits(cond)
    v.l0 = (m & a.l0) | (^m & b.l0)
    v.l1 = (m & a.l1) | (^m & b.l1)
    v.l2 = (m & a.l2) | (^m & b.l2)
    v.l3 = (m & a.l3) | (^m & b.l3)
    v.l4 = (m & a.l4) | (^m & b.l4)
    v.l5 = (m & a.l5) | (^m & b.l5)
    v.l6 = (m & a.l6) | (^m & b.l6)
    v.l7 = (m & a.l7) | (^m & b.l7)
    return v
}

// Swap swaps v and u if cond == 1 or leaves them unchanged if cond == 0.
func (v *Element) Swap(u *Element, cond int) {
    m := mask64Bits(cond)
    t := m & (v.l0 ^ u.l0)
    v.l0 ^= t
    u.l0 ^= t
    t = m & (v.l1 ^ u.l1)
    v.l1 ^= t
    u.l1 ^= t
    t = m & (v.l2 ^ u.l2)
    v.l2 ^= t
    u.l2 ^= t
    t = m & (v.l3 ^ u.l3)
    v.l3 ^= t
    u.l3 ^= t
    t = m & (v.l4 ^ u.l4)
    v.l4 ^= t
    u.l4 ^= t
    t = m & (v.l5 ^ u.l5)
    v.l5 ^= t
    u.l5 ^= t
    t = m & (v.l6 ^ u.l6)
    v.l6 ^= t
    u.l6 ^= t
    t = m & (v.l7 ^ u.l7)
    v.l7 ^= t
    u.l7 ^= t
}

// carryPropagate brings the limbs below 56 bits by applying the reduction
// identity (a * 2^448 + b = a * 2^224 + a + b) to the l7 carry. TODO inline
func (v *Element) carryPropagate() *Element {
    c0 := v.l0 >> 56
    c1 := v.l1 >> 56
    c2 := v.l2 >> 56
    c3 := v.l3 >> 56
    c4 := v.l4 >> 56
    c5 := v.l5 >> 56
    c6 := v.l6 >> 56
    c7 := v.l7 >> 56

    // c7 is at most 64 - 56 = 8 bits,
    // so the final l0 will be at most 57 bits. Similarly for the rest.
    v.l0 = v.l0&maskLow56Bits + c7
    v.l1 = v.l1&maskLow56Bits + c0
    v.l2 = v.l2&maskLow56Bits + c1
    v.l3 = v.l3&maskLow56Bits + c2
    v.l4 = v.l4&maskLow56Bits + c3 + c7
    v.l5 = v.l5&maskLow56Bits + c4
    v.l6 = v.l6&maskLow56Bits + c5
    v.l7 = v.l7&maskLow56Bits + c6

    return v
}

func (v *Element) Mul32(x *Element, y uint32) *Element {
    x0lo, x0hi := mul56(x.l0, y)
    x1lo, x1hi := mul56(x.l1, y)
    x2lo, x2hi := mul56(x.l2, y)
    x3lo, x3hi := mul56(x.l3, y)
    x4lo, x4hi := mul56(x.l4, y)
    x5lo, x5hi := mul56(x.l5, y)
    x6lo, x6hi := mul56(x.l6, y)
    x7lo, x7hi := mul56(x.l7, y)
    v.l0 = x0lo + x7hi
    v.l1 = x1lo + x0hi
    v.l2 = x2lo + x1hi
    v.l3 = x3lo + x2hi
    v.l4 = x4lo + x3hi + x7hi
    v.l5 = x5lo + x4hi
    v.l6 = x6lo + x5hi
    v.l7 = x7lo + x6hi
    // The hi portions are going to be only 32 bits, plus any previous excess,
    // so we can skip the carry propagation.
    return v
}

// mul56 returns lo + hi * 2^56 = a * b
func mul56(a uint64, b uint32) (lo uint64, hi uint64) {
    h, l := bits.Mul64(a, uint64(b))
    lo = l & maskLow56Bits
    hi = (h << 8) | (l >> 56)
    return
}

type uint128 struct {
    lo, hi uint64
}

// mul64 returns a * b.
func mul64(a, b uint64) uint128 {
    hi, lo := bits.Mul64(a, b)
    return uint128{lo, hi}
}

// addMul64 returns v + a * b.
func addMul64(v uint128, a, b uint64) uint128 {
    hi, lo := bits.Mul64(a, b)
    lo, c := bits.Add64(lo, v.lo, 0)
    hi, _ = bits.Add64(hi, v.hi, c)
    return uint128{lo, hi}
}

func add128(a, b uint128) uint128 {
    lo, c := bits.Add64(a.lo, b.lo, 0)
    hi, _ := bits.Add64(a.hi, b.hi, c)
    return uint128{lo, hi}
}

func lsh128(a uint128) uint128 {
    return uint128{a.lo << 1, (a.hi << 1) | (a.lo >> 63)}
}

// shiftRightBy56 returns a >> 56. a is assumed to be at most 117 bits.
func shiftRightBy56(a uint128) uint64 {
    return (a.hi << (64 - 56)) | (a.lo >> 56)
}

//                                      b7   b6   b5   b4   b3   b2   b1   b0  =
//                                      a7   a6   a5   a4   a3   a2   a1   a0  x
//                                    ----------------------------------------
//                                    a7b0 a6b0 a5b0 a4b0 a3b0 a2b0 a1b0 a0b0  +
//                               a7b1 a6b1 a5b1 a4b1 a3b1 a2b1 a1b1 a0b1       +
//                          a7b2 a6b2 a5b2 a4b2 a3b2 a2b2 a1b2 a0b2            +
//                     a7b3 a6b3 a5b3 a4b3 a3b3 a2b3 a1b3 a0b3                 +
//                a7b4 a6b4 a5b4 a4b4 a3b4 a2b4 a1b4 a0b4                      +
//           a7b5 a6b5 a5b5 a4b5 a3b5 a2b5 a1b5 a0b5                           +
//      a7b6 a6b6 a5b6 a4b6 a3b6 a2b6 a1b6 a0b6                                +
// a7b7 a6b7 a5b7 a4b7 a3b7 a2b7 a1b7 a0b7                                     =
// -----------------------------------------------------------------------------
//  r14  r13  r12  r11  r10   r9   r8   r7   r6   r5   r4   r3   r2   r1   r0
//
// We can then use the reduction identity (a * 2^448 + b = a * 2^224 + a + b) to
// reduce the limbs that would overflow 448 bits. r8 * 2^448 becomes r8 * 2^224 + r8,
// r9 * 2^504 becomes r9 * 2^56 + r9, etc.
//
// r12 * 2^672 = r12 * 2^448 + r12 * 2^224
//   = r12 * 2^224 + r12 + r14 * 2^224
//   = 2 * r12 * 2^224 + r14
//
//   b7        b6          b5          b4          b3   b2        b1        b0  =
//   a7        a6          a5          a4          a3   a2        a1        a0  x
// -------------------  ----------  ----------  ----------     -----     -----
// a7b0      a6b0        a5b0        a4b0        a3b0 a2b0      a1b0      a0b0       +
// a6b1      a5b1        a4b1        a3b1+a7b1   a2b1 a1b1      a0b1      a7b1       +
// a5b2      a4b2        a3b2+a7b2   a2b2+a6b2   a1b2 a0b2      a7b2      a6b2       +
// a4b3      a3b3+a7b3   a2b3+a6b3   a1b3+a5b3   a0b3 a7b3      a6b3      a5b3       +
// a3b4+a7b4 a2b4+a6b4   a1b4+a5b4   a0b4+a4b4   a7b4 a6b4      a5b4      a4b4       +
// a2b5+a6b5 a1b5+a5b5   a0b5+a4b5   a3b5+a7b5*2 a6b5 a5b5      a4b5      a3b5+a7b5  +
// a1b6+a5b6 a0b6+a4b6   a3b6+a7b6*2 a2b6+a6b6*2 a5b6 a4b6      a3b6+a7b6 a2b6+a6b6  +
// a0b7+a4b7 a3b7+a7b7*2 a2b7+a6b7*2 a1b7+a5b7*2 a4b7 a3b7+a7b7 a2b7+a6b7 a1b7+a5b7  =
// --------------------------------------------------------------------------------
//        r7          r6          r5          r4   r3        r2        r1        r0

func (v *Element) Mul(a, b *Element) *Element {
    a0 := a.l0
    a1 := a.l1
    a2 := a.l2
    a3 := a.l3
    a4 := a.l4
    a5 := a.l5
    a6 := a.l6
    a7 := a.l7

    b0 := b.l0
    b1 := b.l1
    b2 := b.l2
    b3 := b.l3
    b4 := b.l4
    b5 := b.l5
    b6 := b.l6
    b7 := b.l7

    a7b1 := mul64(a7, b1)
    a6b2 := mul64(a6, b2)
    a5b3 := mul64(a5, b3)
    a4b4 := mul64(a4, b4)
    a3b5 := mul64(a3, b5)
    a2b6 := mul64(a2, b6)
    a1b7 := mul64(a1, b7)

    a7b2 := mul64(a7, b2)
    a6b3 := mul64(a6, b3)
    a5b4 := mul64(a5, b4)
    a4b5 := mul64(a4, b5)
    a3b6 := mul64(a3, b6)
    a2b7 := mul64(a2, b7)

    a7b3 := mul64(a7, b3)
    a6b4 := mul64(a6, b4)
    a5b5 := mul64(a5, b5)
    a4b6 := mul64(a4, b6)
    a3b7 := mul64(a3, b7)

    a7b4 := mul64(a7, b4)
    a6b5 := mul64(a6, b5)
    a5b6 := mul64(a5, b6)
    a4b7 := mul64(a4, b7)

    a7b5 := mul64(a7, b5)
    a6b6 := mul64(a6, b6)
    a5b7 := mul64(a5, b7)

    a7b6 := mul64(a7, b6)
    a6b7 := mul64(a6, b7)

    a7b7 := mul64(a7, b7)

    // r0 = a0b0 + a7b1 + a6b2 + a5b3 + a4b4 + a3b5+a7b5 + a2b6+a6b6 + a1b7+a5b7
    r0 := mul64(a0, b0)
    r0 = add128(r0, a7b1)
    r0 = add128(r0, a6b2)
    r0 = add128(r0, a5b3)
    r0 = add128(r0, a4b4)
    r0 = add128(r0, a3b5)
    r0 = add128(r0, a7b5)
    r0 = add128(r0, a2b6)
    r0 = add128(r0, a6b6)
    r0 = add128(r0, a1b7)
    r0 = add128(r0, a5b7)

    // r1 = a1b0 + a0b1 + a7b2 + a6b3 + a5b4 + a4b5 + a3b6+a7b6 + a2b7+a6b7
    r1 := mul64(a1, b0)
    r1 = addMul64(r1, a0, b1)
    r1 = addMul64(r1, a7, b2)
    r1 = addMul64(r1, a6, b3)
    r1 = addMul64(r1, a5, b4)
    r1 = addMul64(r1, a4, b5)
    r1 = addMul64(r1, a3, b6)
    r1 = add128(r1, a7b6)
    r1 = addMul64(r1, a2, b7)
    r1 = add128(r1, a6b7)

    // r2 = a2b0 + a1b1 + a0b2 + a7b3 + a6b4 + a5b5 + a4b6 + a3b7+a7b7
    r2 := mul64(a2, b0)
    r2 = addMul64(r2, a1, b1)
    r2 = addMul64(r2, a0, b2)
    r2 = add128(r2, a7b3)
    r2 = add128(r2, a6b4)
    r2 = add128(r2, a5b5)
    r2 = add128(r2, a4b6)
    r2 = add128(r2, a3b7)
    r2 = add128(r2, a7b7)

    // r3 = a3b0 + a2b1 + a1b2 + a0b3 + a7b4 + a6b5 + a5b6 + a4b7
    r3 := mul64(a3, b0)
    r3 = addMul64(r3, a2, b1)
    r3 = addMul64(r3, a1, b2)
    r3 = addMul64(r3, a0, b3)
    r3 = add128(r3, a7b4)
    r3 = add128(r3, a6b5)
    r3 = add128(r3, a5b6)
    r3 = add128(r3, a4b7)

    // r4 = a4b0 + a3b1+a7b1 + a2b2+a6b2 + a1b3+a5b3 + a0b4+a4b4 + a3b5+a7b5*2 + a2b6+a6b6*2 + a1b7+a5b7*2
    r4 := add128(a7b5, a6b6)
    r4 = add128(r4, a5b7)
    r4 = lsh128(r4)
    r4 = addMul64(r4, a4, b0)
    r4 = addMul64(r4, a3, b1)
    r4 = add128(r4, a7b1)
    r4 = addMul64(r4, a2, b2)
    r4 = add128(r4, a6b2)
    r4 = addMul64(r4, a1, b3)
    r4 = add128(r4, a5b3)
    r4 = addMul64(r4, a0, b4)
    r4 = addMul64(r4, a4, b4)
    r4 = addMul64(r4, a3, b5)
    r4 = addMul64(r4, a2, b6)
    r4 = addMul64(r4, a1, b7)

    // r5 = a5b0 + a4b1 + a3b2+a7b2 + a2b3+a6b3 + a1b4+a5b4 + a0b5+a4b5 + a3b6+a7b6*2 + a2b7+a6b7*2
    r5 := lsh128(add128(a7b6, a6b7))
    r5 = addMul64(r5, a5, b0)
    r5 = addMul64(r5, a4, b1)
    r5 = addMul64(r5, a3, b2)
    r5 = add128(r5, a7b2)
    r5 = addMul64(r5, a2, b3)
    r5 = add128(r5, a6b3)
    r5 = addMul64(r5, a1, b4)
    r5 = add128(r5, a5b4)
    r5 = addMul64(r5, a0, b5)
    r5 = add128(r5, a4b5)
    r5 = add128(r5, a3b6)
    r5 = add128(r5, a2b7)

    // r6 = a6b0 + a5b1 + a4b2 + a3b3+a7b3 + a2b4+a6b4 + a1b5+a5b5 + a0b6+a4b6 + a3b7+a7b7*2
    r6 := mul64(a6, b0)
    r6 = addMul64(r6, a5, b1)
    r6 = addMul64(r6, a4, b2)
    r6 = addMul64(r6, a3, b3)
    r6 = add128(r6, a7b3)
    r6 = addMul64(r6, a2, b4)
    r6 = add128(r6, a6b4)
    r6 = addMul64(r6, a1, b5)
    r6 = add128(r6, a5b5)
    r6 = addMul64(r6, a0, b6)
    r6 = add128(r6, a4b6)
    r6 = addMul64(r6, a3, b7)
    r6 = add128(r6, lsh128(a7b7))

    // r7 = a7b0 + a6b1 + a5b2 + a4b3 + a3b4+a7b4 + a2b5+a6b5 + a1b6+a5b6 + a0b7+a4b7
    r7 := mul64(a7, b0)
    r7 = addMul64(r7, a6, b1)
    r7 = addMul64(r7, a5, b2)
    r7 = addMul64(r7, a4, b3)
    r7 = addMul64(r7, a3, b4)
    r7 = add128(r7, a7b4)
    r7 = addMul64(r7, a2, b5)
    r7 = add128(r7, a6b5)
    r7 = addMul64(r7, a1, b6)
    r7 = add128(r7, a5b6)
    r7 = addMul64(r7, a0, b7)
    r7 = add128(r7, a4b7)

    c0 := shiftRightBy56(r0)
    c1 := shiftRightBy56(r1)
    c2 := shiftRightBy56(r2)
    c3 := shiftRightBy56(r3)
    c4 := shiftRightBy56(r4)
    c5 := shiftRightBy56(r5)
    c6 := shiftRightBy56(r6)
    c7 := shiftRightBy56(r7)

    rr0 := r0.lo&maskLow56Bits + c7
    rr1 := r1.lo&maskLow56Bits + c0
    rr2 := r2.lo&maskLow56Bits + c1
    rr3 := r3.lo&maskLow56Bits + c2
    rr4 := r4.lo&maskLow56Bits + c3 + c7
    rr5 := r5.lo&maskLow56Bits + c4
    rr6 := r6.lo&maskLow56Bits + c5
    rr7 := r7.lo&maskLow56Bits + c6
    *v = Element{rr0, rr1, rr2, rr3, rr4, rr5, rr6, rr7}

    // propagate carry
    c0 = v.l0 >> 56
    c1 = v.l1 >> 56
    c2 = v.l2 >> 56
    c3 = v.l3 >> 56
    c4 = v.l4 >> 56
    c5 = v.l5 >> 56
    c6 = v.l6 >> 56
    c7 = v.l7 >> 56

    // c7 is at most 64 - 56 = 8 bits,
    // so the final l0 will be at most 57 bits. Similarly for the rest.
    v.l0 = v.l0&maskLow56Bits + c7
    v.l1 = v.l1&maskLow56Bits + c0
    v.l2 = v.l2&maskLow56Bits + c1
    v.l3 = v.l3&maskLow56Bits + c2
    v.l4 = v.l4&maskLow56Bits + c3 + c7
    v.l5 = v.l5&maskLow56Bits + c4
    v.l6 = v.l6&maskLow56Bits + c5
    v.l7 = v.l7&maskLow56Bits + c6

    return v
}

//                                      a7   a6   a5   a4   a3   a2   a1   a0  =
//                                      a7   a6   a5   a4   a3   a2   a1   a0  x
//                                    ----------------------------------------
//                                    a7a0 a6a0 a5a0 a4a0 a3a0 a2a0 a1a0 a0a0  +
//                               a7a1 a6a1 a5a1 a4a1 a3a1 a2a1 a1a1 a0a1       +
//                          a7a2 a6a2 a5a2 a4a2 a3a2 a2a2 a1a2 a0a2            +
//                     a7a3 a6a3 a5a3 a4a3 a3a3 a2a3 a1a3 a0a3                 +
//                a7a4 a6a4 a5a4 a4a4 a3a4 a2a4 a1a4 a0a4                      +
//           a7a5 a6a5 a5a5 a4a5 a3a5 a2a5 a1a5 a0a5                           +
//      a7a6 a6a6 a5a6 a4a6 a3a6 a2a6 a1a6 a0a6                                +
// a7a7 a6a7 a5a7 a4a7 a3a7 a2a7 a1a7 a0a7                                     =
// -----------------------------------------------------------------------------
//  r14  r13  r12  r11  r10   r9   r8   r7   r6   r5   r4   r3   r2   r1   r0
//
// We can then use the reduction identity (a * 2^448 + b = a * 2^224 + a + b) to
// reduce the limbs that would overflow 448 bits. r8 * 2^448 becomes r8 * 2^224 + r8,
// r9 * 2^504 becomes r9 * 2^56 + r9, etc.
//
// r12 * 2^672 = r12 * 2^448 + r12 * 2^224
//   = r12 * 2^224 + r12 + r14 * 2^224
//   = 2 * r12 * 2^224 + r14
//
//   a7        a6          a5          a4          a3   a2        a1        a0  =
//   a7        a6          a5          a4          a3   a2        a1        a0  x
// -------------------  ----------  ----------  ----------     -----     -----
// a0a7      a0a6        a0a5        a0a4        a0a3 a0a2      a0a1      a0a0       +
// a1a6      a1a5        a1a4        a1a3+a1a7   a1a2 a1a1      a0a1      a1a7       +
// a2a5      a2a4        a2a3+a2a7   a2a2+a2a6   a1a2 a0a2      a2a7      a2a6       +
// a3a4      a3a3+a3a7   a2a3+a3a6   a1a3+a3a5   a0a3 a3a7      a3a6      a3a5       +
// a3a4+a4a7 a2a4+a4a6   a1a4+a4a5   a0a4+a4a4   a4a7 a4a6      a4a5      a4a4       +
// a2a5+a5a6 a1a5+a5a5   a0a5+a4a5   a3a5+a5a7*2 a5a6 a5a5      a4a5      a3a5+a5a7  +
// a1a6+a5a6 a0a6+a4a6   a3a6+a6a7*2 a2a6+a6a6*2 a5a6 a4a6      a3a6+a6a7 a2a6+a6a6  +
// a0a7+a4a7 a3a7+a7a7*2 a2a7+a6a7*2 a1a7+a5a7*2 a4a7 a3a7+a7a7 a2a7+a6a7 a1a7+a5a7  =
// --------------------------------------------------------------------------------
//        r7          r6          r5          r4   r3        r2        r1        r0

func (v *Element) Square(a *Element) *Element {
    a0 := a.l0
    a1 := a.l1
    a2 := a.l2
    a3 := a.l3
    a4 := a.l4
    a5 := a.l5
    a6 := a.l6
    a7 := a.l7

    a1a7 := mul64(a1, a7)

    a2a6 := mul64(a2, a6)
    a2a7 := mul64(a2, a7)

    a3a5 := mul64(a3, a5)
    a3a6 := mul64(a3, a6)
    a3a7 := mul64(a3, a7)

    a4a4 := mul64(a4, a4)
    a4a5 := mul64(a4, a5)
    a4a6 := mul64(a4, a6)
    a4a7 := mul64(a4, a7)

    a5a5 := mul64(a5, a5)
    a5a6 := mul64(a5, a6)
    a5a7 := mul64(a5, a7)

    a6a6 := mul64(a6, a6)
    a6a7 := mul64(a6, a7)

    a7a7 := mul64(a7, a7)

    // r0 = a0a0 + a1a7 + a2a6 + a3a5 + a4a4 + a3a5+a5a7 + a2a6+a6a6 + a1a7+a5a7
    r0 := a1a7
    r0 = add128(r0, a2a6)
    r0 = add128(r0, a3a5)
    r0 = add128(r0, a5a7)
    r0 = lsh128(r0)
    r0 = addMul64(r0, a0, a0)
    r0 = add128(r0, a4a4)
    r0 = add128(r0, a6a6)

    // r1 = a0a1 + a0a1 + a2a7 + a3a6 + a4a5 + a4a5 + a3a6+a6a7 + a2a7+a6a7
    r1 := mul64(a0, a1)
    r1 = add128(r1, a2a7)
    r1 = add128(r1, a3a6)
    r1 = add128(r1, a4a5)
    r1 = add128(r1, a6a7)
    r1 = lsh128(r1)

    // r2 = a0a2 + a1a1 + a0a2 + a3a7 + a4a6 + a5a5 + a4a6 + a3a7+a7a7
    r2 := mul64(a0, a2)
    r2 = add128(r2, a3a7)
    r2 = add128(r2, a4a6)
    r2 = lsh128(r2)
    r2 = addMul64(r2, a1, a1)
    r2 = add128(r2, a5a5)
    r2 = addMul64(r2, a7, a7)

    // r3 = a0a3 + a1a2 + a1a2 + a0a3 + a4a7 + a5a6 + a5a6 + a4a7
    r3 := mul64(a0, a3)
    r3 = addMul64(r3, a1, a2)
    r3 = add128(r3, a4a7)
    r3 = add128(r3, a5a6)
    r3 = lsh128(r3)

    // r4 = a0a4 + a1a3+a1a7 + a2a2+a2a6 + a1a3+a3a5 + a0a4+a4a4 + a3a5+a5a7*2 + a2a6+a6a6*2 + a1a7+a5a7*2
    r4 := lsh128(a5a7)
    r4 = add128(r4, a6a6)
    r4 = addMul64(r4, a0, a4)
    r4 = addMul64(r4, a1, a3)
    r4 = add128(r4, a1a7)
    r4 = add128(r4, a2a6)
    r4 = add128(r4, a3a5)
    r4 = lsh128(r4)
    r4 = addMul64(r4, a2, a2)
    r4 = add128(r4, a4a4)

    // r5 = a0a5 + a1a4 + a2a3+a2a7 + a2a3+a3a6 + a1a4+a4a5 + a0a5+a4a5 + a3a6+a6a7*2 + a2a7+a6a7*2
    r5 := lsh128(a6a7)
    r5 = addMul64(r5, a0, a5)
    r5 = addMul64(r5, a1, a4)
    r5 = addMul64(r5, a2, a3)
    r5 = add128(r5, a2a7)
    r5 = add128(r5, a3a6)
    r5 = add128(r5, a4a5)
    r5 = lsh128(r5)

    // r6 = a0a6 + a1a5 + a2a4 + a3a3+a3a7 + a2a4+a4a6 + a1a5+a5a5 + a0a6+a4a6 + a3a7+a7a7*2
    r6 := a7a7
    r6 = addMul64(r6, a0, a6)
    r6 = addMul64(r6, a1, a5)
    r6 = addMul64(r6, a2, a4)
    r6 = add128(r6, a3a7)
    r6 = add128(r6, a4a6)
    r6 = lsh128(r6)
    r6 = addMul64(r6, a3, a3)
    r6 = add128(r6, a5a5)

    // r7 = a0a7 + a1a6 + a2a5 + a3a4 + a3a4+a4a7 + a2a5+a5a6 + a1a6+a5a6 + a0a7+a4a7
    r7 := mul64(a0, a7)
    r7 = addMul64(r7, a1, a6)
    r7 = addMul64(r7, a2, a5)
    r7 = addMul64(r7, a3, a4)
    r7 = add128(r7, a4a7)
    r7 = add128(r7, a5a6)
    r7 = lsh128(r7)

    c0 := shiftRightBy56(r0)
    c1 := shiftRightBy56(r1)
    c2 := shiftRightBy56(r2)
    c3 := shiftRightBy56(r3)
    c4 := shiftRightBy56(r4)
    c5 := shiftRightBy56(r5)
    c6 := shiftRightBy56(r6)
    c7 := shiftRightBy56(r7)

    rr0 := r0.lo&maskLow56Bits + c7
    rr1 := r1.lo&maskLow56Bits + c0
    rr2 := r2.lo&maskLow56Bits + c1
    rr3 := r3.lo&maskLow56Bits + c2
    rr4 := r4.lo&maskLow56Bits + c3 + c7
    rr5 := r5.lo&maskLow56Bits + c4
    rr6 := r6.lo&maskLow56Bits + c5
    rr7 := r7.lo&maskLow56Bits + c6
    *v = Element{rr0, rr1, rr2, rr3, rr4, rr5, rr6, rr7}

    // propagate carry
    c0 = v.l0 >> 56
    c1 = v.l1 >> 56
    c2 = v.l2 >> 56
    c3 = v.l3 >> 56
    c4 = v.l4 >> 56
    c5 = v.l5 >> 56
    c6 = v.l6 >> 56
    c7 = v.l7 >> 56

    // c7 is at most 64 - 56 = 8 bits,
    // so the final l0 will be at most 57 bits. Similarly for the rest.
    v.l0 = v.l0&maskLow56Bits + c7
    v.l1 = v.l1&maskLow56Bits + c0
    v.l2 = v.l2&maskLow56Bits + c1
    v.l3 = v.l3&maskLow56Bits + c2
    v.l4 = v.l4&maskLow56Bits + c3 + c7
    v.l5 = v.l5&maskLow56Bits + c4
    v.l6 = v.l6&maskLow56Bits + c5
    v.l7 = v.l7&maskLow56Bits + c6

    return v
}

// Inv sets v = 1/z mod p, and returns v.
func (v *Element) Inv(z *Element) *Element {
    // Inversion is implemented as exponentiation with exponent p − 2.

    var x Element
    x.Power446(z)
    x.Square(&x)
    x.Square(&x) // 2^448 - 2^224 - 4

    return v.Mul(&x, z) // 2^448 - 2^224 - 3
}

// Power446 sets v = v ^ ((p-3)/4) mod p, and returns v.
// (p-3)/4 is 2^446 - 2^222 - 1.
func (v *Element) Power446(z *Element) *Element {
    var z1, z2, z3 Element
    z1.Square(z)   // 2^1
    z2.Square(&z1) // 2^2
    z3.Mul(z, &z1)
    z3.Mul(&z3, &z2) // 2^3 - 1

    var z6 Element
    z6.Square(&z3)
    z6.Square(&z6)
    z6.Square(&z6)
    z6.Mul(&z6, &z3) // 2^6 - 1

    var z9 Element
    z9.Square(&z6)
    z9.Square(&z9)
    z9.Square(&z9)
    z9.Mul(&z9, &z3) // 2^9 - 1

    var z18 Element
    z18.Square(&z9)
    for i := 1; i < 9; i++ {
        z18.Square(&z18)
    }
    z18.Mul(&z18, &z9) // 2^18 - 1

    var z37 Element
    z37.Square(&z18)
    for i := 1; i < 18; i++ {
        z37.Square(&z37)

    }
    z37.Mul(&z37, &z18)
    z37.Square(&z37)
    z37.Mul(&z37, z) // 2^37 - 1

    var z111 Element
    z111.Square(&z37)
    for i := 1; i < 37; i++ {
        z111.Square(&z111)
    }
    z111.Mul(&z111, &z37)
    for i := 0; i < 37; i++ {
        z111.Square(&z111)
    }
    z111.Mul(&z111, &z37) // 2^111 - 1

    var z222 Element
    z222.Square(&z111)
    for i := 1; i < 111; i++ {
        z222.Square(&z222)
    }
    z222.Mul(&z222, &z111) // 2^222 - 1

    var z223 Element
    z223.Square(&z222)
    z223.Mul(&z223, z) // 2^223 - 1

    var x Element
    x.Square(&z223)
    for i := 1; i < 223; i++ {
        x.Square(&x)
    }
    v.Mul(&x, &z222) // 2^446 - 2^222 - 1

    return v
}

// SqrtRatio sets r to the non-negative square root of the ratio of u and v.
//
// If u/v is square, SqrtRatio returns r and 1. If u/v is not square, SqrtRatio
// sets r according to Section 5.2 of draft-irtf-cfrg-ristretto255-decaf448-04,
// and returns r and 0.
func (r *Element) SqrtRatio(u, v *Element) (rr *Element, wasSquare int) {
    var uv Element
    uv.Mul(u, v)
    uv.Power446(&uv)
    r.Mul(u, &uv)

    var check Element
    check.Square(r)
    check.Mul(v, &check)
    wasSquare = check.Equal(u)

    return r, wasSquare
}
