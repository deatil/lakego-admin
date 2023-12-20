package sm9curve

// For details of the algorithms used, see "Multiplication and Squaring on
// Pairing-Friendly Fields, Devegili et al.
// http://eprint.iacr.org/2006/471.pdf.

import (
    "math/big"
)

// gfP12 implements the field of size p¹² as a quadratic extension of gfP6
// where ω²=τ.
type gfP12 struct {
    x, y gfP6 // value is xω + y
}

var gfP12Gen *gfP12 = &gfP12{
    x: gfP6{
        x: gfP2{
            x: gfP{0x513dbc73240138c0, 0xabb39aec5c957a11, 0x2faa8e49d7294f9e, 0x6add5d304ff681e4},
            y: gfP{0xb2952202400c1da7, 0x80b83e27e364ef9e, 0x470c9526f8a186a9, 0x2915ca5028d8c43a},
        },
        y: gfP2{
            x: gfP{0x4218861fe3f5ae7a, 0x6b3033ab3ff1a59e, 0xa521950378e93610, 0x57f69a60583f2847},
            y: gfP{0x36e4f111918e1d96, 0xa03359bb9780a652, 0x2b2bec1b0d4a4889, 0xa007d436fab467af},
        },
        z: gfP2{
            x: gfP{0xa694d7e16d92625e, 0xec1913f15868b801, 0xaf96b4f8ed1fe80a, 0xa8479f1ac2fa5546},
            y: gfP{0xa5f0fb058177d49a, 0xb1d16f82e2bc6f18, 0x3c71fa129547a729, 0x131b1915db10160d},
        },
    },
    y: gfP6{
        x: gfP2{
            x: gfP{0x8ac4f31a5925bcaa, 0x5dc0eb332aa6389b, 0x6f2a25a38ccf247b, 0x65f67ec80c2071b1},
            y: gfP{0x60cefaed398c3437, 0x218dc8827ef0b202, 0x4829899e34b7d867, 0x04a3b982875c7af0},
        },
        y: gfP2{
            x: gfP{0xdf54e1763084afc2, 0x692b84e37dde076c, 0x1f3a4948122abae0, 0x581ce11e4bdc56d2},
            y: gfP{0x543d49f9a76e0a4f, 0x8d247091f17aedc4, 0xe2fbea6edc133ad9, 0x8c4e46e8a40fd106},
        },
        z: gfP2{
            x: gfP{0x075d7fecd8189dd4, 0x1406e3c8e83f2e82, 0x2f84a872d0d0cc2e, 0x7829f5625230bba8},
            y: gfP{0x104d9126d962e5cd, 0x5e3472092a2ec2b0, 0xf56cf3a688b849e8, 0x84974f923ff12208},
        },
    },
}

func (e *gfP12) String() string {
    return "(" + e.x.String() + "," + e.y.String() + ")"
}

func (e *gfP12) Set(a *gfP12) *gfP12 {
    e.x.Set(&a.x)
    e.y.Set(&a.y)
    return e
}

func (e *gfP12) SetZero() *gfP12 {
    e.x.SetZero()
    e.y.SetZero()
    return e
}

func (e *gfP12) SetOne() *gfP12 {
    e.x.SetZero()
    e.y.SetOne()
    return e
}

func (e *gfP12) IsZero() bool {
    return e.x.IsZero() && e.y.IsZero()
}

func (e *gfP12) IsOne() bool {
    return e.x.IsZero() && e.y.IsOne()
}

func (e *gfP12) Conjugate(a *gfP12) *gfP12 {
    e.x.Neg(&a.x)
    e.y.Set(&a.y)
    return e
}

func (e *gfP12) Neg(a *gfP12) *gfP12 {
    e.x.Neg(&a.x)
    e.y.Neg(&a.y)
    return e
}

// Frobenius computes (xω+y)^p = x^p ω·ξ^((p-1)/6) + y^p
func (e *gfP12) Frobenius(a *gfP12) *gfP12 {
    e.x.Frobenius(&a.x)
    e.y.Frobenius(&a.y)
    e.x.MulGFP(&e.x, xiToPMinus1Over6)
    return e
}

// FrobeniusP2 computes (xω+y)^p² = x^p² ω·ξ^((p²-1)/6) + y^p²
func (e *gfP12) FrobeniusP2(a *gfP12) *gfP12 {
    e.x.FrobeniusP2(&a.x)
    e.x.MulGFP(&e.x, xiToPSquaredMinus1Over6)
    e.y.FrobeniusP2(&a.y)
    return e
}

//func (e *gfP12) FrobeniusP4(a *gfP12) *gfP12 {
//	e.x.FrobeniusP4(&a.x)
//	e.x.MulGFP(&e.x, xiToPSquaredMinus1Over3)
//	e.y.FrobeniusP4(&a.y)
//	return e
//}

func (e *gfP12) Add(a, b *gfP12) *gfP12 {
    e.x.Add(&a.x, &b.x)
    e.y.Add(&a.y, &b.y)
    return e
}

func (e *gfP12) Sub(a, b *gfP12) *gfP12 {
    e.x.Sub(&a.x, &b.x)
    e.y.Sub(&a.y, &b.y)
    return e
}

func (e *gfP12) Mul(a, b *gfP12) *gfP12 {
    tx := (&gfP6{}).Mul(&a.x, &b.y)
    t := (&gfP6{}).Mul(&b.x, &a.y)
    tx.Add(tx, t)

    ty := (&gfP6{}).Mul(&a.y, &b.y)
    t.Mul(&a.x, &b.x).MulTau(t)

    e.x.Set(tx)
    e.y.Add(ty, t)
    return e
}

func (e *gfP12) MulScalar(a *gfP12, b *gfP6) *gfP12 {
    e.x.Mul(&e.x, b)
    e.y.Mul(&e.y, b)
    return e
}

func (c *gfP12) Exp(a *gfP12, power *big.Int) *gfP12 {
    sum := (&gfP12{}).SetOne()
    t := &gfP12{}

    for i := power.BitLen() - 1; i >= 0; i-- {
        t.Square(sum)
        if power.Bit(i) != 0 {
            sum.Mul(t, a)
        } else {
            sum.Set(t)
        }
    }

    c.Set(sum)
    return c
}

func (e *gfP12) Square(a *gfP12) *gfP12 {
    // Complex squaring algorithm
    v0 := (&gfP6{}).Mul(&a.x, &a.y)

    t := (&gfP6{}).MulTau(&a.x)
    t.Add(&a.y, t)
    ty := (&gfP6{}).Add(&a.x, &a.y)
    ty.Mul(ty, t)
    ty.Sub(ty, v0)
    t.MulTau(v0)
    ty.Sub(ty, t)

    tx := new(gfP6).Add(v0, v0)
    e.x.Set(tx)
    e.y.Set(ty)
    return e
}

func (e *gfP12) Square1(a *gfP12) *gfP12 {
    tmp1 := new(gfP6).Mul(&a.x, &a.y)
    tmp2 := new(gfP6).Add(&a.x, &a.y)

    tmp3 := new(gfP6).MulTau(&a.x)
    ty := new(gfP6).Add(tmp3, &a.y)
    ty.Mul(ty, tmp2)
    ty.Sub(ty, tmp1)

    tmp2.MulTau(tmp1)
    ty.Sub(ty, tmp2)

    tx := new(gfP6).Add(tmp1, tmp1)

    e.x.Set(tx)
    e.y.Set(ty)
    return e
}

func (e *gfP12) Invert(a *gfP12) *gfP12 {
    // See "Implementing cryptographic pairings", M. Scott, section 3.2.
    // ftp://136.206.11.249/pub/crypto/pairings.pdf
    t1, t2 := &gfP6{}, &gfP6{}

    t1.Square(&a.x)
    t2.Square(&a.y)
    t1.MulTau(t1).Sub(t2, t1)
    t2.Invert(t1)

    e.x.Neg(&a.x)
    e.y.Set(&a.y)
    e.MulScalar(e, t2)
    return e
}

func montEncodeGfp12(a gfP12) (b gfP12) {
    var b1, b2, b3, b4, b5, b6, b7, b8, b9, b10, b11, b12 = gfP{}, gfP{}, gfP{}, gfP{}, gfP{}, gfP{}, gfP{}, gfP{}, gfP{}, gfP{}, gfP{}, gfP{}
    montEncode(&b1, &a.x.x.x)
    montEncode(&b2, &a.x.x.y)
    montEncode(&b3, &a.x.y.x)
    montEncode(&b4, &a.x.y.y)
    montEncode(&b5, &a.x.z.x)
    montEncode(&b6, &a.x.z.y)
    montEncode(&b7, &a.y.x.x)
    montEncode(&b8, &a.y.x.y)
    montEncode(&b9, &a.y.y.x)
    montEncode(&b10, &a.y.y.y)
    montEncode(&b11, &a.y.z.x)
    montEncode(&b12, &a.y.z.y)
    b = gfP12{gfP6{gfP2{b1, b2}, gfP2{b3, b4}, gfP2{b5, b6}},
        gfP6{gfP2{b7, b8}, gfP2{b9, b10}, gfP2{b11, b12}}}
    return b
}

func montDecodeGfp12(a gfP12) (b gfP12) {
    var b1, b2, b3, b4, b5, b6, b7, b8, b9, b10, b11, b12 = gfP{}, gfP{}, gfP{}, gfP{}, gfP{}, gfP{}, gfP{}, gfP{}, gfP{}, gfP{}, gfP{}, gfP{}
    montDecode(&b1, &a.x.x.x)
    montDecode(&b2, &a.x.x.y)
    montDecode(&b3, &a.x.y.x)
    montDecode(&b4, &a.x.y.y)
    montDecode(&b5, &a.x.z.x)
    montDecode(&b6, &a.x.z.y)
    montDecode(&b7, &a.y.x.x)
    montDecode(&b8, &a.y.x.y)
    montDecode(&b9, &a.y.y.x)
    montDecode(&b10, &a.y.y.y)
    montDecode(&b11, &a.y.z.x)
    montDecode(&b12, &a.y.z.y)
    b = gfP12{gfP6{gfP2{b1, b2}, gfP2{b3, b4}, gfP2{b5, b6}},
        gfP6{gfP2{b7, b8}, gfP2{b9, b10}, gfP2{b11, b12}}}
    return b
}
