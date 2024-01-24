package field

import (
    "errors"
    "math/bits"
    "strconv"
)

type Element struct {
    l0 uint64
    l1 uint64
    l2 uint64
    l3 uint64
}

func (v *Element) One() {
    v.l0 = 1
    v.l1 = 0
    v.l2 = 0
    v.l3 = 0
}

func (v *Element) Zero() {
    v.l0 = 0
    v.l1 = 0
    v.l2 = 0
    v.l3 = 0
}

func (v *Element) SetBytes(x []byte) error {
    if len(x) > 32 {
        panic("too long bytes: " + strconv.Itoa(len(x)))
    }
    var buf [32]byte
    copy(buf[32-len(x):], x)
    return setBytes(v, &buf)
}

func setBytes(v *Element, buf *[32]byte) error {
    v.l3 = uint64(buf[0])<<56 + uint64(buf[1])<<48 +
        uint64(buf[2])<<40 + uint64(buf[3])<<32 +
        uint64(buf[4])<<24 + uint64(buf[5])<<16 +
        uint64(buf[6])<<8 + uint64(buf[7])
    v.l2 = uint64(buf[8])<<56 + uint64(buf[9])<<48 +
        uint64(buf[10])<<40 + uint64(buf[11])<<32 +
        uint64(buf[12])<<24 + uint64(buf[13])<<16 +
        uint64(buf[14])<<8 + uint64(buf[15])
    v.l1 = uint64(buf[16])<<56 + uint64(buf[17])<<48 +
        uint64(buf[18])<<40 + uint64(buf[19])<<32 +
        uint64(buf[20])<<24 + uint64(buf[21])<<16 +
        uint64(buf[22])<<8 + uint64(buf[23])
    v.l0 = uint64(buf[24])<<56 + uint64(buf[25])<<48 +
        uint64(buf[26])<<40 + uint64(buf[27])<<32 +
        uint64(buf[28])<<24 + uint64(buf[29])<<16 +
        uint64(buf[30])<<8 + uint64(buf[31])

    _, c := bits.Add64(v.l0, 0x1000003d1, 0)
    _, c = bits.Add64(v.l1, 0, c)
    _, c = bits.Add64(v.l2, 0, c)
    _, c = bits.Add64(v.l3, 0, c)
    if c != 0 {
        return errors.New("overflow")
    }
    return nil
}

func (v *Element) Bytes() []byte {
    var buf [32]byte
    buf[31] = byte(v.l0)
    buf[30] = byte(v.l0 >> 8)
    buf[29] = byte(v.l0 >> 16)
    buf[28] = byte(v.l0 >> 24)
    buf[27] = byte(v.l0 >> 32)
    buf[26] = byte(v.l0 >> 40)
    buf[25] = byte(v.l0 >> 48)
    buf[24] = byte(v.l0 >> 56)
    buf[23] = byte(v.l1)
    buf[22] = byte(v.l1 >> 8)
    buf[21] = byte(v.l1 >> 16)
    buf[20] = byte(v.l1 >> 24)
    buf[19] = byte(v.l1 >> 32)
    buf[18] = byte(v.l1 >> 40)
    buf[17] = byte(v.l1 >> 48)
    buf[16] = byte(v.l1 >> 56)
    buf[15] = byte(v.l2)
    buf[14] = byte(v.l2 >> 8)
    buf[13] = byte(v.l2 >> 16)
    buf[12] = byte(v.l2 >> 24)
    buf[11] = byte(v.l2 >> 32)
    buf[10] = byte(v.l2 >> 40)
    buf[9] = byte(v.l2 >> 48)
    buf[8] = byte(v.l2 >> 56)
    buf[7] = byte(v.l3)
    buf[6] = byte(v.l3 >> 8)
    buf[5] = byte(v.l3 >> 16)
    buf[4] = byte(v.l3 >> 24)
    buf[3] = byte(v.l3 >> 32)
    buf[2] = byte(v.l3 >> 40)
    buf[1] = byte(v.l3 >> 48)
    buf[0] = byte(v.l3 >> 56)
    return buf[:]
}

// 2^256 + 2^256 - 2^32 - 2^9 - 2^8 - 2^7 - 2^6 - 2^4 - 1 - v = 2^256 - v

// reduce reduces v modulo 2^256 - 2^32 - 2^9 - 2^8 - 2^7 - 2^6 - 2^4 - 1 and returns it.
func (v *Element) reduce() *Element {
    var c uint64

    // If v >= 2^256 - 2^32 - 2^9 - 2^8 - 2^7 - 2^6 - 2^4 - 1,
    // then v + 2^32 + 2^9 + 2^8 + 2^7 + 2^6 + 2^4 + 1 >= 2^256,
    // which would overflow 2^256 - 1, generating a carry.
    // That is, c will be 0 if v < 2^256 - 2^32 - 2^9 - 2^8 - 2^7 - 2^6 - 2^4 - 1, and 1 otherwise.
    _, c = bits.Add64(v.l0, 0x1000003d1, 0)
    _, c = bits.Add64(v.l1, 0, c)
    _, c = bits.Add64(v.l2, 0, c)
    _, c = bits.Add64(v.l3, 0, c)

    // If v < 2^256 - 2^32 - 2^9 - 2^8 - 2^7 - 2^6 - 2^4 - 1 and c = 0,
    // this will be a no-op. Otherwise, it's
    // effectively applying the reduction identity to the carry.
    v.l0, c = bits.Add64(v.l0, c*0x1000003d1, 0)
    v.l1, c = bits.Add64(v.l1, 0, c)
    v.l2, c = bits.Add64(v.l2, 0, c)
    v.l3 += c // no additional carry
    return v
}

// Equal returns 1 if v and u are equal, and 0 otherwise.
func (v *Element) Equal(x *Element) int {
    var c uint64
    c |= v.l0 ^ x.l0
    c |= v.l1 ^ x.l1
    c |= v.l2 ^ x.l2
    c |= v.l3 ^ x.l3

    c = (c & 0xFFFFFFFF) | (c >> 32)
    c--
    return int(c >> 63)
}

// IsZero returns 1 if v equals zero, and 0 otherwise.
func (v *Element) IsZero() int {
    var c uint64
    c |= v.l0
    c |= v.l1
    c |= v.l2
    c |= v.l3

    c = (c & 0xFFFFFFFF) | (c >> 32)
    c--
    return int(c >> 63)
}

// Set sets v = a, and returns v.
func (v *Element) Set(x *Element) *Element {
    *v = *x
    return v
}

// Select sets v to a if cond == 1, and to b if cond == 0.
func (v *Element) Select(a, b *Element, cond int) *Element {
    m := -uint64(cond)
    v.l0 = (m & a.l0) | (^m & b.l0)
    v.l1 = (m & a.l1) | (^m & b.l1)
    v.l2 = (m & a.l2) | (^m & b.l2)
    v.l3 = (m & a.l3) | (^m & b.l3)
    return v
}

// Swap swaps v and u if cond == 1 or leaves them unchanged if cond == 0, and returns v.
func (v *Element) Swap(u *Element, cond int) {
    m := -uint64(cond)
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
}

// Add sets v = a + b, and returns v.
func (v *Element) Add(x, y *Element) *Element {
    var c uint64
    v.l0, c = bits.Add64(x.l0, y.l0, 0)
    v.l1, c = bits.Add64(x.l1, y.l1, c)
    v.l2, c = bits.Add64(x.l2, y.l2, c)
    v.l3, c = bits.Add64(x.l3, y.l3, c)

    v.l0, c = bits.Add64(v.l0, c*0x1000003d1, 0)
    v.l1, c = bits.Add64(v.l1, 0, c)
    v.l2, c = bits.Add64(v.l2, 0, c)
    v.l3 += c // no additional carry

    return v.reduce()
}

// Subtract sets v = a - b, and returns v.
func (v *Element) Sub(x, y *Element) *Element {
    var minusB Element
    minusB.Neg(y)
    return v.Add(x, &minusB)
}

// Negate sets v = -a, and returns v.
func (v *Element) Neg(x *Element) *Element {
    // v = p - x
    var c uint64
    v.l0, c = bits.Sub64(0xfffffffefffffc2f, x.l0, 0)
    v.l1, c = bits.Sub64(0xffffffffffffffff, x.l1, c)
    v.l2, c = bits.Sub64(0xffffffffffffffff, x.l2, c)
    v.l3, _ = bits.Sub64(0xffffffffffffffff, x.l3, c)
    // x < p, so here is no carry

    return v // no need to reduce
}

// Mul sets v = x * y, and returns v.
func (v *Element) Mul(a, b *Element) *Element {
    a0b0h, a0b0l := bits.Mul64(a.l0, b.l0)
    a0b1h, a0b1l := bits.Mul64(a.l0, b.l1)
    a0b2h, a0b2l := bits.Mul64(a.l0, b.l2)
    a0b3h, a0b3l := bits.Mul64(a.l0, b.l3)
    a1b0h, a1b0l := bits.Mul64(a.l1, b.l0)
    a1b1h, a1b1l := bits.Mul64(a.l1, b.l1)
    a1b2h, a1b2l := bits.Mul64(a.l1, b.l2)
    a1b3h, a1b3l := bits.Mul64(a.l1, b.l3)
    a2b0h, a2b0l := bits.Mul64(a.l2, b.l0)
    a2b1h, a2b1l := bits.Mul64(a.l2, b.l1)
    a2b2h, a2b2l := bits.Mul64(a.l2, b.l2)
    a2b3h, a2b3l := bits.Mul64(a.l2, b.l3)
    a3b0h, a3b0l := bits.Mul64(a.l3, b.l0)
    a3b1h, a3b1l := bits.Mul64(a.l3, b.l1)
    a3b2h, a3b2l := bits.Mul64(a.l3, b.l2)
    a3b3h, a3b3l := bits.Mul64(a.l3, b.l3)

    //                                 a3    a2    a1    a0  x
    //                                 b3    b2    b1    b0  =
    //                        -------------------------------
    //                        a3b0h a2b0h a1b0h a0b0h        +
    //                              a3b0l a2b0l a1b0l a0b0l  +
    //                  a3b1h a2b1h a1b1h a0b1h              +
    //                        a3b1l a2b1l a1b1l a0b1l        +
    //            a3b2h a2b2h a1b2h a0b2h                    +
    //                  a3b2l a2b2l a1b2l a0b2l              +
    //      a3b3h a2b3h a1b3h a0b3h                          +
    //            a3b3l a2b3l a1b3l a0b3l                    +
    //   -----------------------------------------------------
    //   r8    r7    r6    r5    r4    r3    r2    r1    r0

    //                                 a3    a2    a1    a0  x
    //                                 b3    b2    b1    b0  =
    //                        -------------------------------
    //      a3b3h a2b3h a1b3h a0b3h a3b0l a2b0l a1b0l a0b0l  +
    //                        a3b0h a2b0h a1b0h a0b0h        +
    //                        a3b1l a2b1l a1b1l a0b1l        +
    //                  a3b1h a2b1h a1b1h a0b1h              +
    //                  a3b2l a2b2l a1b2l a0b2l              +
    //            a3b2h a2b2h a1b2h a0b2h                    +
    //            a3b3l a2b3l a1b3l a0b3l                    +
    //   -----------------------------------------------------
    //   r8    r7    r6    r5    r4    r3    r2    r1    r0

    r0, r1, r2, r3, r4, r5, r6, r7 := a0b0l, a1b0l, a2b0l, a3b0l, a0b3h, a1b3h, a2b3h, a3b3h

    a0b1, c := bits.Add64(a0b0h, a0b1l, 0)
    a1b1, c := bits.Add64(a1b0h, a1b1l, c)
    a2b1, c := bits.Add64(a2b0h, a2b1l, c)
    a3b1, a4b1 := bits.Add64(a3b0h, a3b1l, c)

    a0b2, c := bits.Add64(a0b1h, a0b2l, 0)
    a1b2, c := bits.Add64(a1b1h, a1b2l, c)
    a2b2, c := bits.Add64(a2b1h, a2b2l, c)
    a3b2, a4b2 := bits.Add64(a3b1h, a3b2l, c)

    a0b3, c := bits.Add64(a0b2h, a0b3l, 0)
    a1b3, c := bits.Add64(a1b2h, a1b3l, c)
    a2b3, c := bits.Add64(a2b2h, a2b3l, c)
    a3b3, a4b3 := bits.Add64(a3b2h, a3b3l, c)

    r3, c = bits.Add64(r3, a0b3, 0)
    r4, c = bits.Add64(r4, a1b3, c)
    r5, c = bits.Add64(r5, a2b3, c)
    r6, c = bits.Add64(r6, a3b3, c)
    r7, c = bits.Add64(r7, a4b3, c)
    r8 := c

    r2, c = bits.Add64(r2, a0b2, 0)
    r3, c = bits.Add64(r3, a1b2, c)
    r4, c = bits.Add64(r4, a2b2, c)
    r5, c = bits.Add64(r5, a3b2, c)
    r6, c = bits.Add64(r6, a4b2, c)
    r7, c = bits.Add64(r7, 0, c)
    r8 += c

    r1, c = bits.Add64(r1, a0b1, 0)
    r2, c = bits.Add64(r2, a1b1, c)
    r3, c = bits.Add64(r3, a2b1, c)
    r4, c = bits.Add64(r4, a3b1, c)
    r5, c = bits.Add64(r5, a4b1, c)
    r6, c = bits.Add64(r6, 0, c)
    r7, c = bits.Add64(r7, 0, c)
    r8 += c

    // reduce
    // 2^(256+n) = (2^256 - 2^32 - 2^9 - 2^8 - 2^7 - 2^6 - 2^4 - 1) * 2^n  mod p
    var h, l uint64
    h, l = bits.Mul64(r8, 0x1000003d1)
    r4, c = bits.Add64(r4, l, 0)
    r5, c = bits.Add64(r5, h, c)
    r6, c = bits.Add64(r6, 0, c)
    r7, c = bits.Add64(r7, 0, c)
    r8 = c // r8 is now 0 or 1

    h, l = bits.Mul64(r7, 0x1000003d1)
    r3, c = bits.Add64(r3, l, 0)
    r4, c = bits.Add64(r4, h, c)
    r5, c = bits.Add64(r5, 0, c)
    r6, c = bits.Add64(r6, 0, c)
    r7 = c // r7 is now 0 or 1

    h, l = bits.Mul64(r6, 0x1000003d1)
    r2, c = bits.Add64(r2, l, 0)
    r3, c = bits.Add64(r3, h, c)
    r4, c = bits.Add64(r4, 0, c)
    r5, c = bits.Add64(r5, 0, c)
    r6 = c // r6 is now 0 or 1

    h, l = bits.Mul64(r5, 0x1000003d1)
    r1, c = bits.Add64(r1, l, 0)
    r2, c = bits.Add64(r2, h, c)
    r3, c = bits.Add64(r3, 0, c)
    r4, c = bits.Add64(r4, 0, c)
    r5 = c // r5 is now 0 or 1

    h, l = bits.Mul64(r4, 0x1000003d1)
    r0, c = bits.Add64(r0, l, 0)
    r1, c = bits.Add64(r1, h, c)
    r2, c = bits.Add64(r2, 0, c)
    r3, c = bits.Add64(r3, 0, c)
    r4 = c // r4 is now 0 or 1

    // reduce again
    h, l = bits.Mul64(r8, 0x1000003d1)
    r4, c = bits.Add64(r4, l, 0)
    r5, c = bits.Add64(r5, h, c)
    r6, c = bits.Add64(r6, 0, c)
    r7 += c // no additional carry

    h, l = bits.Mul64(r7, 0x1000003d1)
    r3, c = bits.Add64(r3, l, 0)
    r4, c = bits.Add64(r4, h, c)
    r5, c = bits.Add64(r5, 0, c)
    r6 += c // no additional carry

    h, l = bits.Mul64(r6, 0x1000003d1)
    r2, c = bits.Add64(r2, l, 0)
    r3, c = bits.Add64(r3, h, c)
    r4, c = bits.Add64(r4, 0, c)
    r5 += c // no additional carry

    h, l = bits.Mul64(r5, 0x1000003d1)
    r1, c = bits.Add64(r1, l, 0)
    r2, c = bits.Add64(r2, h, c)
    r3, c = bits.Add64(r3, 0, c)
    r4 += c // no additional carry

    h, l = bits.Mul64(r4, 0x1000003d1)
    r0, c = bits.Add64(r0, l, 0)
    r1, c = bits.Add64(r1, h, c)
    r2, c = bits.Add64(r2, 0, c)
    r3 += c // no additional carry

    v.l0 = r0
    v.l1 = r1
    v.l2 = r2
    v.l3 = r3
    return v.reduce()
}

// Square sets v = x * x, and returns v.
func (v *Element) Square(x *Element) *Element {
    a0a0h, a0a0l := bits.Mul64(x.l0, x.l0)
    a0a1h, a0a1l := bits.Mul64(x.l0, x.l1)
    a0a2h, a0a2l := bits.Mul64(x.l0, x.l2)
    a0a3h, a0a3l := bits.Mul64(x.l0, x.l3)

    a1a1h, a1a1l := bits.Mul64(x.l1, x.l1)
    a1a2h, a1a2l := bits.Mul64(x.l1, x.l2)
    a1a3h, a1a3l := bits.Mul64(x.l1, x.l3)

    a2a2h, a2a2l := bits.Mul64(x.l2, x.l2)
    a2a3h, a2a3l := bits.Mul64(x.l2, x.l3)

    a3a3h, a3a3l := bits.Mul64(x.l3, x.l3)

    //                                 a3    a2    a1    a0  x
    //                                 a3    a2    a1    a0  =
    //                        -------------------------------
    //                        a3a0h a2a0h a1a0h a0a0h        +
    //                              a3a0l a2a0l a1a0l a0a0l  +
    //                  a3a1h a2a1h a1a1h a0a1h              +
    //                        a3a1l a2a1l a1a1l a0a1l        +
    //            a3a2h a2a2h a1a2h a0a2h                    +
    //                  a3a2l a2a2l a1a2l a0a2l              +
    //      a3a3h a2a3h a1a3h a0a3h                          +
    //            a3a3l a2a3l a1a3l a0a3l                    +
    //   -----------------------------------------------------
    //   r8    r7    r6    r5    r4    r3    r2    r1    r0
    //
    //                                 a3    a2    a1    a0  x
    //                                 a3    a2    a1    a0  =
    //                        -------------------------------
    //      a3a3h a2a3h a1a3h a0a3h a0a3l a0a2l a0a1l a0a0l  +
    //                        a0a3h a0a2h a0a1h a0a0h        +
    //                        a1a3l a1a2l a1a1l a0a1l        +
    //                  a1a3h a1a2h a1a1h a0a1h              +
    //                  a2a3l a2a2l a1a2l a0a2l              +
    //            a2a3h a2a2h a1a2h a0a2h                    +
    //            a3a3l a2a3l a1a3l a0a3l                    +
    //   -----------------------------------------------------
    //   r8    r7    r6    r5    r4    r3    r2    r1    r0
    r0, r1, r2, r3, r4, r5, r6, r7, r8 := a0a0l, a0a1l, a0a2l, a0a3l, a0a3h, a1a3h, a2a3h, a3a3h, uint64(0)

    a0a1, c := bits.Add64(a0a1l, a0a0h, 0)
    a1a1, c := bits.Add64(a1a1l, a0a1h, c)
    a2a1, c := bits.Add64(a1a2l, a0a2h, c)
    a3a1, a4a1 := bits.Add64(a1a3l, a0a3h, c)

    a0a2, c := bits.Add64(a0a2l, a0a1h, 0)
    a1a2, c := bits.Add64(a1a2l, a1a1h, c)
    a2a2, c := bits.Add64(a2a2l, a1a2h, c)
    a3a2, a4a2 := bits.Add64(a2a3l, a1a3h, c)

    a0a3, c := bits.Add64(a0a3l, a0a2h, 0)
    a1a3, c := bits.Add64(a1a3l, a1a2h, c)
    a2a3, c := bits.Add64(a2a3l, a2a2h, c)
    a3a3, a4a3 := bits.Add64(a3a3l, a2a3h, c)

    r3, c = bits.Add64(r3, a0a3, 0)
    r4, c = bits.Add64(r4, a1a3, c)
    r5, c = bits.Add64(r5, a2a3, c)
    r6, c = bits.Add64(r6, a3a3, c)
    r7, c = bits.Add64(r7, a4a3, c)
    r8 += c

    r2, c = bits.Add64(r2, a0a2, c)
    r3, c = bits.Add64(r3, a1a2, c)
    r4, c = bits.Add64(r4, a2a2, c)
    r5, c = bits.Add64(r5, a3a2, c)
    r6, c = bits.Add64(r6, a4a2, c)
    r7, c = bits.Add64(r7, 0, c)
    r8 += c

    r1, c = bits.Add64(r1, a0a1, 0)
    r2, c = bits.Add64(r2, a1a1, c)
    r3, c = bits.Add64(r3, a2a1, c)
    r4, c = bits.Add64(r4, a3a1, c)
    r5, c = bits.Add64(r5, a4a1, c)
    r6, c = bits.Add64(r6, 0, c)
    r7, c = bits.Add64(r7, 0, c)
    r8 += c

    // reduce
    // 2^(256+n) = (2^256 - 2^32 - 2^9 - 2^8 - 2^7 - 2^6 - 2^4 - 1) * 2^n  mod p
    var h, l uint64
    h, l = bits.Mul64(r8, 0x1000003d1)
    r4, c = bits.Add64(r4, l, 0)
    r5, c = bits.Add64(r5, h, c)
    r6, c = bits.Add64(r6, 0, c)
    r7, c = bits.Add64(r7, 0, c)
    r8 = c // r8 is now 0 or 1

    h, l = bits.Mul64(r7, 0x1000003d1)
    r3, c = bits.Add64(r3, l, 0)
    r4, c = bits.Add64(r4, h, c)
    r5, c = bits.Add64(r5, 0, c)
    r6, c = bits.Add64(r6, 0, c)
    r7 = c // r7 is now 0 or 1

    h, l = bits.Mul64(r6, 0x1000003d1)
    r2, c = bits.Add64(r2, l, 0)
    r3, c = bits.Add64(r3, h, c)
    r4, c = bits.Add64(r4, 0, c)
    r5, c = bits.Add64(r5, 0, c)
    r6 = c // r6 is now 0 or 1

    h, l = bits.Mul64(r5, 0x1000003d1)
    r1, c = bits.Add64(r1, l, 0)
    r2, c = bits.Add64(r2, h, c)
    r3, c = bits.Add64(r3, 0, c)
    r4, c = bits.Add64(r4, 0, c)
    r5 = c // r5 is now 0 or 1

    h, l = bits.Mul64(r4, 0x1000003d1)
    r0, c = bits.Add64(r0, l, 0)
    r1, c = bits.Add64(r1, h, c)
    r2, c = bits.Add64(r2, 0, c)
    r3, c = bits.Add64(r3, 0, c)
    r4 = c // r4 is now 0 or 1

    // reduce again
    h, l = bits.Mul64(r8, 0x1000003d1)
    r4, c = bits.Add64(r4, l, 0)
    r5, c = bits.Add64(r5, h, c)
    r6, c = bits.Add64(r6, 0, c)
    r7 += c // no additional carry

    h, l = bits.Mul64(r7, 0x1000003d1)
    r3, c = bits.Add64(r3, l, 0)
    r4, c = bits.Add64(r4, h, c)
    r5, c = bits.Add64(r5, 0, c)
    r6 += c // no additional carry

    h, l = bits.Mul64(r6, 0x1000003d1)
    r2, c = bits.Add64(r2, l, 0)
    r3, c = bits.Add64(r3, h, c)
    r4, c = bits.Add64(r4, 0, c)
    r5 += c // no additional carry

    h, l = bits.Mul64(r5, 0x1000003d1)
    r1, c = bits.Add64(r1, l, 0)
    r2, c = bits.Add64(r2, h, c)
    r3, c = bits.Add64(r3, 0, c)
    r4 += c // no additional carry

    h, l = bits.Mul64(r4, 0x1000003d1)
    r0, c = bits.Add64(r0, l, 0)
    r1, c = bits.Add64(r1, h, c)
    r2, c = bits.Add64(r2, 0, c)
    r3 += c // no additional carry

    v.l0 = r0
    v.l1 = r1
    v.l2 = r2
    v.l3 = r3
    return v.reduce()
}

// Inv sets v = 1/z mod p, and returns v.
func (v *Element) Inv(z *Element) *Element {
    var z1, z2, z3 Element
    z1.Square(z)
    z2.Square(&z1)
    z3.Square(&z2)

    var z4 Element
    z4.Mul(z, &z1)
    z4.Mul(&z4, &z2)
    z4.Mul(&z4, &z3) // = 2^4 - 1

    var z8 Element
    z8.Square(&z4)
    z8.Square(&z8)
    z8.Square(&z8)
    z8.Square(&z8)
    z8.Mul(&z8, &z4) // = 2^8 - 1

    var z16 Element
    z16.Square(&z8)
    for i := 1; i < 8; i++ {
        z16.Square(&z16)
    }
    z16.Mul(&z16, &z8) // = 2^16 - 1

    var z32 Element
    z32.Square(&z16)
    for i := 1; i < 16; i++ {
        z32.Square(&z32)
    }
    z32.Mul(&z32, &z16) // = 2^32 - 1

    var z64 Element
    z64.Square(&z32)
    for i := 1; i < 32; i++ {
        z64.Square(&z64)
    }
    z64.Mul(&z64, &z32) // = 2^64 - 1

    var z128 Element
    z128.Square(&z64)
    for i := 1; i < 64; i++ {
        z128.Square(&z128)
    }
    z128.Mul(&z128, &z64) // = 2^128 - 1

    var x Element
    x.Square(&z128)
    for i := 1; i < 64; i++ {
        x.Square(&x)
    }
    x.Mul(&x, &z64) // = 2^192 - 1

    for i := 0; i < 16; i++ {
        x.Square(&x)
    }
    x.Mul(&x, &z16) // = 2^208 - 1

    for i := 0; i < 8; i++ {
        x.Square(&x)
    }
    x.Mul(&x, &z8) // = 2^216 - 1

    x.Square(&x)
    x.Square(&x)
    x.Square(&x)
    x.Square(&x)
    x.Mul(&x, &z4) // = 2^220 - 1

    x.Square(&x)
    x.Mul(&x, z) // = 2^221 - 1

    x.Square(&x)
    x.Mul(&x, z) // = 2^222 - 1

    x.Square(&x)
    x.Mul(&x, z) // = 2^223 - 1

    for i := 0; i < 17; i++ {
        x.Square(&x)
    }
    x.Mul(&x, &z16) // = 2^240 - 2^16 - 1

    x.Square(&x)
    x.Square(&x)
    x.Square(&x)
    x.Square(&x)
    x.Mul(&x, &z4) // = 2^244 - 2^20 - 1

    x.Square(&x)
    x.Mul(&x, z) // = 2^245 - 2^21 - 1

    x.Square(&x)
    x.Mul(&x, z) // = 2^246 - 2^22 - 1

    x.Square(&x)
    x.Square(&x)
    x.Square(&x)
    x.Square(&x)
    x.Square(&x)
    x.Mul(&x, z) // = 2^251 - 2^27 - 2^4 - 2^3 - 2^2 - 2^1 - 1

    x.Square(&x)
    x.Square(&x)
    x.Mul(&x, z) // = 2^253 - 2^29 - 2^6 - 2^5 - 2^4 - 2^3 - 2^1 - 1

    x.Square(&x)
    x.Mul(&x, z) // = 2^254 - 2^30 - 2^7 - 2^6 - 2^5 - 2^4 - 2^2 - 1

    x.Square(&x)
    x.Square(&x)
    x.Mul(&x, z) // = 2^256 - 2^32 - 2^9 - 2^8 - 2^7 - 2^6 - 2^4 - 3
    return v.Set(&x)
}
