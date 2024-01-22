package field

import (
    "errors"
    "strconv"
    "math/big"
)

const (
    bottom28Bits = 0xFFFFFFF
    bottom29Bits = 0x1FFFFFFF
)

// p256Zero31 is 0 mod p.
var zero31 = []uint32{
    0x7FFFFFF8, 0x3FFFFFFC, 0x800003FC, 0x3FFFDFFC,
    0x7FFFFFFC, 0x3FFFFFFC, 0x7FFFFFFC, 0x37FFFFFC,
    0x7FFFFFFC,
}

var P, RInverse *big.Int

func init() {
    P, _ = new(big.Int).SetString("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF", 16)
    RInverse, _ = new(big.Int).SetString("7ffffffd80000002fffffffe000000017ffffffe800000037ffffffc80000002", 16)
}

type Element struct {
    l [9]uint32
}

func (this *Element) Zero() {
    this.l = [9]uint32{}
}

func (this *Element) SetBytes(x []byte) error {
    if len(x) > 32 {
        return errors.New("too long bytes: " + strconv.Itoa(len(x)))
    }

    this.FromBig(new(big.Int).SetBytes(x))

    return nil
}

func (this *Element) Bytes() []byte {
    return this.ToBig().Bytes()
}

// Equal returns 1 if v and u are equal, and 0 otherwise.
func (this *Element) Equal(x *Element) int {
    var c uint32

    for i := 0; i < 9; i++ {
        c |= this.l[i] ^ x.l[i]
    }

    c = (c & 0xFFFF) | (c >> 16)
    c--

    return int(c >> 31)
}

// Equal returns 1 if v equals zero, and 0 otherwise.
func (this *Element) IsZero() int {
    var c uint32

    for i := 0; i < 9; i++ {
        c |= this.l[i]
    }

    c = (c & 0xFFFF) | (c >> 16)
    c--

    return int(c >> 31)
}

// Set sets v = a, and returns v.
func (this *Element) Set(x *Element) *Element {
    *this = *x
    return this
}

// Set field data
func (this *Element) SetUint32(x [9]uint32) *Element {
    copy(this.l[:], x[:])
    return this
}

// Get field data
func (this *Element) GetUint32() [9]uint32 {
    return this.l
}

// c = a + b
func (this *Element) Add(a, b *Element) *Element {
    carry := uint32(0)

    for i := 0; ; i++ {
        this.l[i] = a.l[i] + b.l[i]
        this.l[i] += carry

        carry = this.l[i] >> 29

        this.l[i] &= bottom29Bits
        i++

        if i == 9 {
            break
        }

        this.l[i] = a.l[i] + b.l[i]
        this.l[i] += carry

        carry = this.l[i] >> 28

        this.l[i] &= bottom28Bits
    }

    return this.reduce(carry)
}

// c = a - b
func (this *Element) Sub(a, b *Element) *Element {
    var carry uint32

    for i := 0; ; i++ {
        this.l[i] = a.l[i] - b.l[i]
        this.l[i] += zero31[i]
        this.l[i] += carry

        carry = this.l[i] >> 29

        this.l[i] &= bottom29Bits
        i++

        if i == 9 {
            break
        }

        this.l[i] = a.l[i] - b.l[i]
        this.l[i] += zero31[i]
        this.l[i] += carry

        carry = this.l[i] >> 28

        this.l[i] &= bottom28Bits
    }

    return this.reduce(carry)
}

// c = a * b
func (this *Element) Mul(a, b *Element) *Element {
    var tmp [17]uint64

    tmp[0] = uint64(a.l[0]) * uint64(b.l[0])
    tmp[1] = uint64(a.l[0])*(uint64(b.l[1])<<0) +
        uint64(a.l[1])*(uint64(b.l[0])<<0)
    tmp[2] = uint64(a.l[0])*(uint64(b.l[2])<<0) +
        uint64(a.l[1])*(uint64(b.l[1])<<1) +
        uint64(a.l[2])*(uint64(b.l[0])<<0)
    tmp[3] = uint64(a.l[0])*(uint64(b.l[3])<<0) +
        uint64(a.l[1])*(uint64(b.l[2])<<0) +
        uint64(a.l[2])*(uint64(b.l[1])<<0) +
        uint64(a.l[3])*(uint64(b.l[0])<<0)
    tmp[4] = uint64(a.l[0])*(uint64(b.l[4])<<0) +
        uint64(a.l[1])*(uint64(b.l[3])<<1) +
        uint64(a.l[2])*(uint64(b.l[2])<<0) +
        uint64(a.l[3])*(uint64(b.l[1])<<1) +
        uint64(a.l[4])*(uint64(b.l[0])<<0)
    tmp[5] = uint64(a.l[0])*(uint64(b.l[5])<<0) +
        uint64(a.l[1])*(uint64(b.l[4])<<0) +
        uint64(a.l[2])*(uint64(b.l[3])<<0) +
        uint64(a.l[3])*(uint64(b.l[2])<<0) +
        uint64(a.l[4])*(uint64(b.l[1])<<0) +
        uint64(a.l[5])*(uint64(b.l[0])<<0)
    tmp[6] = uint64(a.l[0])*(uint64(b.l[6])<<0) +
        uint64(a.l[1])*(uint64(b.l[5])<<1) +
        uint64(a.l[2])*(uint64(b.l[4])<<0) +
        uint64(a.l[3])*(uint64(b.l[3])<<1) +
        uint64(a.l[4])*(uint64(b.l[2])<<0) +
        uint64(a.l[5])*(uint64(b.l[1])<<1) +
        uint64(a.l[6])*(uint64(b.l[0])<<0)
    tmp[7] = uint64(a.l[0])*(uint64(b.l[7])<<0) +
        uint64(a.l[1])*(uint64(b.l[6])<<0) +
        uint64(a.l[2])*(uint64(b.l[5])<<0) +
        uint64(a.l[3])*(uint64(b.l[4])<<0) +
        uint64(a.l[4])*(uint64(b.l[3])<<0) +
        uint64(a.l[5])*(uint64(b.l[2])<<0) +
        uint64(a.l[6])*(uint64(b.l[1])<<0) +
        uint64(a.l[7])*(uint64(b.l[0])<<0)

    // tmp[8] has the greatest value but doesn't overflow. See logic in
    // p256Square.
    tmp[8] = uint64(a.l[0])*(uint64(b.l[8])<<0) +
        uint64(a.l[1])*(uint64(b.l[7])<<1) +
        uint64(a.l[2])*(uint64(b.l[6])<<0) +
        uint64(a.l[3])*(uint64(b.l[5])<<1) +
        uint64(a.l[4])*(uint64(b.l[4])<<0) +
        uint64(a.l[5])*(uint64(b.l[3])<<1) +
        uint64(a.l[6])*(uint64(b.l[2])<<0) +
        uint64(a.l[7])*(uint64(b.l[1])<<1) +
        uint64(a.l[8])*(uint64(b.l[0])<<0)
    tmp[9] = uint64(a.l[1])*(uint64(b.l[8])<<0) +
        uint64(a.l[2])*(uint64(b.l[7])<<0) +
        uint64(a.l[3])*(uint64(b.l[6])<<0) +
        uint64(a.l[4])*(uint64(b.l[5])<<0) +
        uint64(a.l[5])*(uint64(b.l[4])<<0) +
        uint64(a.l[6])*(uint64(b.l[3])<<0) +
        uint64(a.l[7])*(uint64(b.l[2])<<0) +
        uint64(a.l[8])*(uint64(b.l[1])<<0)
    tmp[10] = uint64(a.l[2])*(uint64(b.l[8])<<0) +
        uint64(a.l[3])*(uint64(b.l[7])<<1) +
        uint64(a.l[4])*(uint64(b.l[6])<<0) +
        uint64(a.l[5])*(uint64(b.l[5])<<1) +
        uint64(a.l[6])*(uint64(b.l[4])<<0) +
        uint64(a.l[7])*(uint64(b.l[3])<<1) +
        uint64(a.l[8])*(uint64(b.l[2])<<0)
    tmp[11] = uint64(a.l[3])*(uint64(b.l[8])<<0) +
        uint64(a.l[4])*(uint64(b.l[7])<<0) +
        uint64(a.l[5])*(uint64(b.l[6])<<0) +
        uint64(a.l[6])*(uint64(b.l[5])<<0) +
        uint64(a.l[7])*(uint64(b.l[4])<<0) +
        uint64(a.l[8])*(uint64(b.l[3])<<0)
    tmp[12] = uint64(a.l[4])*(uint64(b.l[8])<<0) +
        uint64(a.l[5])*(uint64(b.l[7])<<1) +
        uint64(a.l[6])*(uint64(b.l[6])<<0) +
        uint64(a.l[7])*(uint64(b.l[5])<<1) +
        uint64(a.l[8])*(uint64(b.l[4])<<0)
    tmp[13] = uint64(a.l[5])*(uint64(b.l[8])<<0) +
        uint64(a.l[6])*(uint64(b.l[7])<<0) +
        uint64(a.l[7])*(uint64(b.l[6])<<0) +
        uint64(a.l[8])*(uint64(b.l[5])<<0)
    tmp[14] = uint64(a.l[6])*(uint64(b.l[8])<<0) +
        uint64(a.l[7])*(uint64(b.l[7])<<1) +
        uint64(a.l[8])*(uint64(b.l[6])<<0)
    tmp[15] = uint64(a.l[7])*(uint64(b.l[8])<<0) +
        uint64(a.l[8])*(uint64(b.l[7])<<0)
    tmp[16] = uint64(a.l[8]) * (uint64(b.l[8]) << 0)

    return this.reduceDegree(tmp)
}

// b = a * a
func (this *Element) Square(a *Element) *Element {
    var tmp [17]uint64

    tmp[0] = uint64(a.l[0]) * uint64(a.l[0])
    tmp[1] = uint64(a.l[0]) * (uint64(a.l[1]) << 1)
    tmp[2] = uint64(a.l[0])*(uint64(a.l[2])<<1) +
        uint64(a.l[1])*(uint64(a.l[1])<<1)
    tmp[3] = uint64(a.l[0])*(uint64(a.l[3])<<1) +
        uint64(a.l[1])*(uint64(a.l[2])<<1)
    tmp[4] = uint64(a.l[0])*(uint64(a.l[4])<<1) +
        uint64(a.l[1])*(uint64(a.l[3])<<2) +
        uint64(a.l[2])*uint64(a.l[2])
    tmp[5] = uint64(a.l[0])*(uint64(a.l[5])<<1) +
        uint64(a.l[1])*(uint64(a.l[4])<<1) +
        uint64(a.l[2])*(uint64(a.l[3])<<1)
    tmp[6] = uint64(a.l[0])*(uint64(a.l[6])<<1) +
        uint64(a.l[1])*(uint64(a.l[5])<<2) +
        uint64(a.l[2])*(uint64(a.l[4])<<1) +
        uint64(a.l[3])*(uint64(a.l[3])<<1)
    tmp[7] = uint64(a.l[0])*(uint64(a.l[7])<<1) +
        uint64(a.l[1])*(uint64(a.l[6])<<1) +
        uint64(a.l[2])*(uint64(a.l[5])<<1) +
        uint64(a.l[3])*(uint64(a.l[4])<<1)

    // tmp[8] has the greatest value of 2**61 + 2**60 + 2**61 + 2**60 + 2**60,
    // which is < 2**64 as required.
    tmp[8] = uint64(a.l[0])*(uint64(a.l[8])<<1) +
        uint64(a.l[1])*(uint64(a.l[7])<<2) +
        uint64(a.l[2])*(uint64(a.l[6])<<1) +
        uint64(a.l[3])*(uint64(a.l[5])<<2) +
        uint64(a.l[4])*uint64(a.l[4])
    tmp[9] = uint64(a.l[1])*(uint64(a.l[8])<<1) +
        uint64(a.l[2])*(uint64(a.l[7])<<1) +
        uint64(a.l[3])*(uint64(a.l[6])<<1) +
        uint64(a.l[4])*(uint64(a.l[5])<<1)
    tmp[10] = uint64(a.l[2])*(uint64(a.l[8])<<1) +
        uint64(a.l[3])*(uint64(a.l[7])<<2) +
        uint64(a.l[4])*(uint64(a.l[6])<<1) +
        uint64(a.l[5])*(uint64(a.l[5])<<1)
    tmp[11] = uint64(a.l[3])*(uint64(a.l[8])<<1) +
        uint64(a.l[4])*(uint64(a.l[7])<<1) +
        uint64(a.l[5])*(uint64(a.l[6])<<1)
    tmp[12] = uint64(a.l[4])*(uint64(a.l[8])<<1) +
        uint64(a.l[5])*(uint64(a.l[7])<<2) +
        uint64(a.l[6])*uint64(a.l[6])
    tmp[13] = uint64(a.l[5])*(uint64(a.l[8])<<1) +
        uint64(a.l[6])*(uint64(a.l[7])<<1)
    tmp[14] = uint64(a.l[6])*(uint64(a.l[8])<<1) +
        uint64(a.l[7])*(uint64(a.l[7])<<1)
    tmp[15] = uint64(a.l[7]) * (uint64(a.l[8]) << 1)
    tmp[16] = uint64(a.l[8]) * uint64(a.l[8])

    return this.reduceDegree(tmp)
}

var Factor = []Element{
    Element{l: [9]uint32{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}},
    Element{l: [9]uint32{0x2, 0x0, 0x1FFFFF00, 0x7FF, 0x0, 0x0, 0x0, 0x2000000, 0x0}},
    Element{l: [9]uint32{0x4, 0x0, 0x1FFFFE00, 0xFFF, 0x0, 0x0, 0x0, 0x4000000, 0x0}},
    Element{l: [9]uint32{0x6, 0x0, 0x1FFFFD00, 0x17FF, 0x0, 0x0, 0x0, 0x6000000, 0x0}},
    Element{l: [9]uint32{0x8, 0x0, 0x1FFFFC00, 0x1FFF, 0x0, 0x0, 0x0, 0x8000000, 0x0}},
    Element{l: [9]uint32{0xA, 0x0, 0x1FFFFB00, 0x27FF, 0x0, 0x0, 0x0, 0xA000000, 0x0}},
    Element{l: [9]uint32{0xC, 0x0, 0x1FFFFA00, 0x2FFF, 0x0, 0x0, 0x0, 0xC000000, 0x0}},
    Element{l: [9]uint32{0xE, 0x0, 0x1FFFF900, 0x37FF, 0x0, 0x0, 0x0, 0xE000000, 0x0}},
    Element{l: [9]uint32{0x10, 0x0, 0x1FFFF800, 0x3FFF, 0x0, 0x0, 0x0, 0x0, 0x01}},
}

func (this *Element) Scalar(a int) *Element {
    return this.Mul(this, &Factor[a])
}

// nonZeroToAllOnes returns:
//   0xffffffff for 0 < x <= 2**31
//   0 for x == 0 or x > 2**31.
func nonZeroToAllOnes(x uint32) uint32 {
    return ((x - 1) >> 31) - 1
}

var reduceCarry = [8 * 9]uint32{
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x2, 0x0, 0x1FFFFF00, 0x7FF, 0x0, 0x0, 0x0, 0x2000000, 0x0,
    0x4, 0x0, 0x1FFFFE00, 0xFFF, 0x0, 0x0, 0x0, 0x4000000, 0x0,
    0x6, 0x0, 0x1FFFFD00, 0x17FF, 0x0, 0x0, 0x0, 0x6000000, 0x0,
    0x8, 0x0, 0x1FFFFC00, 0x1FFF, 0x0, 0x0, 0x0, 0x8000000, 0x0,
    0xA, 0x0, 0x1FFFFB00, 0x27FF, 0x0, 0x0, 0x0, 0xA000000, 0x0,
    0xC, 0x0, 0x1FFFFA00, 0x2FFF, 0x0, 0x0, 0x0, 0xC000000, 0x0,
    0xE, 0x0, 0x1FFFF900, 0x37FF, 0x0, 0x0, 0x0, 0xE000000, 0x0,
}

// carry < 2 ^ 3
func (this *Element) reduce(carry uint32) *Element {
    this.l[0] += reduceCarry[carry * 9 + 0]
    this.l[2] += reduceCarry[carry * 9 + 2]
    this.l[3] += reduceCarry[carry * 9 + 3]
    this.l[7] += reduceCarry[carry * 9 + 7]

    return this
}

func (this *Element) reduceDegree(b [17]uint64) *Element {
    var tmp [18]uint32
    var carry, x, xMask uint32

    // tmp
    // 0  | 1  | 2  | 3  | 4  | 5  | 6  | 7  | 8  |  9 | 10 ...
    // 29 | 28 | 29 | 28 | 29 | 28 | 29 | 28 | 29 | 28 | 29 ...
    tmp[0] = uint32(b[0]) & bottom29Bits
    tmp[1] = uint32(b[0]) >> 29
    tmp[1] |= (uint32(b[0]>>32) << 3) & bottom28Bits
    tmp[1] += uint32(b[1]) & bottom28Bits
    carry = tmp[1] >> 28
    tmp[1] &= bottom28Bits

    for i := 2; i < 17; i++ {
        tmp[i] = (uint32(b[i-2] >> 32)) >> 25
        tmp[i] += (uint32(b[i-1])) >> 28
        tmp[i] += (uint32(b[i-1]>>32) << 4) & bottom29Bits
        tmp[i] += uint32(b[i]) & bottom29Bits
        tmp[i] += carry
        carry = tmp[i] >> 29
        tmp[i] &= bottom29Bits

        i++
        if i == 17 {
            break
        }

        tmp[i] = uint32(b[i-2]>>32) >> 25
        tmp[i] += uint32(b[i-1]) >> 29
        tmp[i] += ((uint32(b[i-1] >> 32)) << 3) & bottom28Bits
        tmp[i] += uint32(b[i]) & bottom28Bits
        tmp[i] += carry

        carry = tmp[i] >> 28
        tmp[i] &= bottom28Bits
    }

    tmp[17] = uint32(b[15]>>32) >> 25
    tmp[17] += uint32(b[16]) >> 29
    tmp[17] += uint32(b[16]>>32) << 3
    tmp[17] += carry

    for i := 0; ; i += 2 {

        tmp[i+1] += tmp[i] >> 29
        x = tmp[i] & bottom29Bits
        tmp[i] = 0
        if x > 0 {
            set4 := uint32(0)
            set7 := uint32(0)
            xMask = nonZeroToAllOnes(x)
            tmp[i+2] += (x << 7) & bottom29Bits
            tmp[i+3] += x >> 22
            if tmp[i+3] < 0x10000000 {
                set4 = 1
                tmp[i+3] += 0x10000000 & xMask
                tmp[i+3] -= (x << 10) & bottom28Bits
            } else {
                tmp[i+3] -= (x << 10) & bottom28Bits
            }
            if tmp[i+4] < 0x20000000 {
                tmp[i+4] += 0x20000000 & xMask
                tmp[i+4] -= set4 // 借位
                tmp[i+4] -= x >> 18
                if tmp[i+5] < 0x10000000 {
                    tmp[i+5] += 0x10000000 & xMask
                    tmp[i+5] -= 1 // 借位
                    if tmp[i+6] < 0x20000000 {
                        set7 = 1
                        tmp[i+6] += 0x20000000 & xMask
                        tmp[i+6] -= 1 // 借位
                    } else {
                        tmp[i+6] -= 1 // 借位
                    }
                } else {
                    tmp[i+5] -= 1
                }
            } else {
                tmp[i+4] -= set4 // 借位
                tmp[i+4] -= x >> 18
            }
            if tmp[i+7] < 0x10000000 {
                tmp[i+7] += 0x10000000 & xMask
                tmp[i+7] -= set7
                tmp[i+7] -= (x << 24) & bottom28Bits
                tmp[i+8] += (x << 28) & bottom29Bits
                if tmp[i+8] < 0x20000000 {
                    tmp[i+8] += 0x20000000 & xMask
                    tmp[i+8] -= 1
                    tmp[i+8] -= x >> 4
                    tmp[i+9] += ((x >> 1) - 1) & xMask
                } else {
                    tmp[i+8] -= 1
                    tmp[i+8] -= x >> 4
                    tmp[i+9] += (x >> 1) & xMask
                }
            } else {
                tmp[i+7] -= set7 // 借位
                tmp[i+7] -= (x << 24) & bottom28Bits
                tmp[i+8] += (x << 28) & bottom29Bits
                if tmp[i+8] < 0x20000000 {
                    tmp[i+8] += 0x20000000 & xMask
                    tmp[i+8] -= x >> 4
                    tmp[i+9] += ((x >> 1) - 1) & xMask
                } else {
                    tmp[i+8] -= x >> 4
                    tmp[i+9] += (x >> 1) & xMask
                }
            }

        }

        if i+1 == 9 {
            break
        }

        tmp[i+2] += tmp[i+1] >> 28
        x = tmp[i+1] & bottom28Bits
        tmp[i+1] = 0

        if x > 0 {
            set5 := uint32(0)
            set8 := uint32(0)
            set9 := uint32(0)

            xMask = nonZeroToAllOnes(x)
            tmp[i+3] += (x << 7) & bottom28Bits
            tmp[i+4] += x >> 21

            if tmp[i+4] < 0x20000000 {
                set5 = 1
                tmp[i+4] += 0x20000000 & xMask
                tmp[i+4] -= (x << 11) & bottom29Bits
            } else {
                tmp[i+4] -= (x << 11) & bottom29Bits
            }

            if tmp[i+5] < 0x10000000 {
                tmp[i+5] += 0x10000000 & xMask
                tmp[i+5] -= set5 // 借位
                tmp[i+5] -= x >> 18
                if tmp[i+6] < 0x20000000 {
                    tmp[i+6] += 0x20000000 & xMask
                    tmp[i+6] -= 1 // 借位
                    if tmp[i+7] < 0x10000000 {
                        set8 = 1
                        tmp[i+7] += 0x10000000 & xMask
                        tmp[i+7] -= 1 // 借位
                    } else {
                        tmp[i+7] -= 1 // 借位
                    }
                } else {
                    tmp[i+6] -= 1 // 借位
                }
            } else {
                tmp[i+5] -= set5 // 借位
                tmp[i+5] -= x >> 18
            }

            if tmp[i+8] < 0x20000000 {
                set9 = 1
                tmp[i+8] += 0x20000000 & xMask
                tmp[i+8] -= set8
                tmp[i+8] -= (x << 25) & bottom29Bits
            } else {
                tmp[i+8] -= set8
                tmp[i+8] -= (x << 25) & bottom29Bits
            }

            if tmp[i+9] < 0x10000000 {
                tmp[i+9] += 0x10000000 & xMask
                tmp[i+9] -= set9 // 借位
                tmp[i+9] -= x >> 4
                tmp[i+10] += (x - 1) & xMask
            } else {
                tmp[i+9] -= set9 // 借位
                tmp[i+9] -= x >> 4
                tmp[i+10] += x & xMask
            }
        }
    }

    carry = uint32(0)
    for i := 0; i < 8; i++ {
        this.l[i] = tmp[i+9]
        this.l[i] += carry
        this.l[i] += (tmp[i+10] << 28) & bottom29Bits
        carry = this.l[i] >> 29
        this.l[i] &= bottom29Bits

        i++
        this.l[i] = tmp[i+9] >> 1
        this.l[i] += carry
        carry = this.l[i] >> 28
        this.l[i] &= bottom28Bits
    }

    this.l[8] = tmp[17]
    this.l[8] += carry
    carry = this.l[8] >> 29
    this.l[8] &= bottom29Bits

    return this.reduce(carry)
}

// b = a
func (this *Element) Dup(a *Element) *Element {
    *this = *a
    return this
}

// Select sets out=in if mask = 0xffffffff in constant time.
//
// On entry: mask is either 0 or 0xffffffff.
func (this *Element) Select(in *Element, mask uint32) *Element {
    for i := 0; i < 9; i++ {
        tmp := mask & (in.l[i] ^ this.l[i])

        this.l[i] ^= tmp
    }

    return this
}

func (this *Element) SelectAffine(table []uint32, mask uint32) *Element {
    for i := 0; i < 9; i++ {
        this.l[i] |= table[0] & mask
        table = table[1:]
    }

    return this
}

func (this *Element) SelectJacobian(in *Element, mask uint32) *Element {
    for i := 0; i < 9; i++ {
        this.l[i] |= in.l[i] & mask
    }

    return this
}

// X = a * R mod P
func (this *Element) FromBig(a *big.Int) *Element {
    x := new(big.Int).Lsh(a, 257)
    x.Mod(x, P)

    for i := 0; i < 9; i++ {
        if bits := x.Bits(); len(bits) > 0 {
            this.l[i] = uint32(bits[0]) & bottom29Bits
        } else {
            this.l[i] = 0
        }

        x.Rsh(x, 29)
        i++

        if i == 9 {
            break
        }

        if bits := x.Bits(); len(bits) > 0 {
            this.l[i] = uint32(bits[0]) & bottom28Bits
        } else {
            this.l[i] = 0
        }

        x.Rsh(x, 28)
    }

    return this
}

// X = this.l
// X = r * R mod P
// r = X * R' mod P
func (this *Element) ToBig() *big.Int {
    r, tm := new(big.Int), new(big.Int)

    r.SetInt64(int64(this.l[8]))

    for i := 7; i >= 0; i-- {
        if (i & 1) == 0 {
            r.Lsh(r, 29)
        } else {
            r.Lsh(r, 28)
        }

        tm.SetInt64(int64(this.l[i]))
        r.Add(r, tm)
    }

    r.Mul(r, RInverse)
    r.Mod(r, P)

    return r
}

