package sm9curve

import "math/big"

// For details of the algorithms used, see "Multiplication and Squaring on
// Pairing-Friendly Fields, Devegili et al.
// http://eprint.iacr.org/2006/471.pdf.

// gfP2 implements a field of size p² as a quadratic extension of the base field
// where i²=-2.
type gfP2 struct {
    x, y gfP // value is xi+y.
}

func gfP2Decode(in *gfP2) *gfP2 {
    out := &gfP2{}
    montDecode(&out.x, &in.x)
    montDecode(&out.y, &in.y)
    return out
}

func (e *gfP2) String() string {
    return "(" + e.x.String() + ", " + e.y.String() + ")"
}

func (e *gfP2) Set(a *gfP2) *gfP2 {
    e.x.Set(&a.x)
    e.y.Set(&a.y)
    return e
}

func (e *gfP2) SetZero() *gfP2 {
    e.x = gfP{0}
    e.y = gfP{0}
    return e
}

func (e *gfP2) SetOne() *gfP2 {
    e.x = gfP{0}
    e.y = *newGFp(1)
    return e
}

func (e *gfP2) Equal(t *gfP2) int {
    var acc uint64
    for i := range e.x {
        acc |= e.x[i] ^ t.x[i]
    }

    for i := range e.y {
        acc |= e.y[i] ^ t.y[i]
    }

    return uint64IsZero(acc)
}

func (e *gfP2) IsZero() bool {
    zero := gfP{0}
    return e.x == zero && e.y == zero
}

func (e *gfP2) IsOne() bool {
    zero, one := gfP{0}, *newGFp(1)
    return e.x == zero && e.y == one
}

func (e *gfP2) Conjugate(a *gfP2) *gfP2 {
    e.y.Set(&a.y)
    gfpNeg(&e.x, &a.x)
    return e
}

func (e *gfP2) Neg(a *gfP2) *gfP2 {
    gfpNeg(&e.x, &a.x)
    gfpNeg(&e.y, &a.y)
    return e
}

func (e *gfP2) Add(a, b *gfP2) *gfP2 {
    gfpAdd(&e.x, &a.x, &b.x)
    gfpAdd(&e.y, &a.y, &b.y)
    return e
}

func (e *gfP2) Sub(a, b *gfP2) *gfP2 {
    gfpSub(&e.x, &a.x, &b.x)
    gfpSub(&e.y, &a.y, &b.y)
    return e
}

// See "Multiplication and Squaring in Pairing-Friendly Fields",
// http://eprint.iacr.org/2006/471.pdf
//(ai+b)(ci+d)=(bd-2ac)+i((a+b)(c+d)-ac-bd)
func (e *gfP2) Mul(a, b *gfP2) *gfP2 {
    tx, t1, t2 := &gfP{}, &gfP{}, &gfP{}
    gfpAdd(t1, &a.x, &a.y) //a+b
    gfpAdd(t2, &b.x, &b.y) //c+d
    gfpMul(tx, t1, t2)

    gfpMul(t1, &a.x, &b.x) //ac
    gfpMul(t2, &a.y, &b.y) //bd
    gfpSub(tx, tx, t1)
    gfpSub(tx, tx, t2) //x=(a+b)(c+d)-ac-bd

    ty := &gfP{}
    gfpSub(ty, t2, t1) //bd-ac
    gfpSub(ty, ty, t1) //bd-2ac

    e.x.Set(tx)
    e.y.Set(ty)
    return e
}

func (e *gfP2) MulScalar(a *gfP2, b *gfP) *gfP2 {
    gfpMul(&e.x, &a.x, b)
    gfpMul(&e.y, &a.y, b)
    return e
}

// MulXi sets e=ξa where ξ=bi=(-1/2)i and then returns e.
func (e *gfP2) MulXi(a *gfP2) *gfP2 {
    // (xi+y)bi = ybi-2bx=-1/2yi+x
    tx := &gfP{}
    ty := &gfP{}
    gfpMul(tx, &a.y, &bi)
    ty.Set(&a.x)

    e.x.Set(tx)
    e.y.Set(ty)
    return e
}

func (e *gfP2) Square(a *gfP2) *gfP2 {
    // Complex squaring algorithm:
    // (xi+y)² = (y²-2x²) + 2*i*x*y
    tx1, tx2, ty1, ty2 := &gfP{}, &gfP{}, &gfP{}, &gfP{}
    gfpMul(tx1, &a.x, &a.y)
    gfpAdd(tx2, tx1, tx1)

    gfpMul(ty1, &a.y, &a.y)
    gfpMul(ty2, &a.x, &a.x)
    ty := &gfP{}
    gfpAdd(ty, ty2, ty2)
    gfpSub(ty1, ty1, ty)

    e.x.Set(tx2)
    e.y.Set(ty1)
    return e
}

func (e *gfP2) Invert(a *gfP2) *gfP2 {
    // See "Implementing cryptographic pairings", M. Scott, section 3.2.
    // ftp://136.206.11.249/pub/crypto/pairings.pdf
    t1, t2 := &gfP{}, &gfP{}
    gfpMul(t1, &a.x, &a.x)
    t3 := &gfP{}
    gfpAdd(t3, t1, t1)
    gfpMul(t2, &a.y, &a.y)
    gfpAdd(t3, t3, t2)

    inv := &gfP{}
    inv.Invert(t3)

    gfpNeg(t1, &a.x)

    gfpMul(&e.x, t1, inv)
    gfpMul(&e.y, &a.y, inv)
    return e
}

func (c *gfP2) GFp2Exp(a *gfP2, b *big.Int) *gfP2 {
    sum := (&gfP2{}).SetOne()
    t := &gfP2{}

    for i := b.BitLen() - 1; i >= 0; i-- {
        t.Square(sum)
        if b.Bit(i) != 0 {
            sum.Mul(t, a)
        } else {
            sum.Set(t)
        }
    }

    c.Set(sum)
    return c
}

// Sqrt method is only required when we implement compressed format
// TODO: use addchain to improve performance for 3 exp operations.
func (ret *gfP2) Sqrt(a *gfP2) *gfP2 {
    // Algorithm 10 https://eprint.iacr.org/2012/685.pdf
    ret.SetZero()
    c := &twistGen.x
    b, b2, bq := &gfP2{}, &gfP2{}, &gfP2{}
    b = b.expPMinus1Over4(a)
    b2.Mul(b, b)
    bq = bq.expP(b)

    t := &gfP2{}
    x0 := &gfP{}
    /* ignore sqrt existing check
    a0 := &gfP2{}
    a0.Exp(b2, p)
    a0.Mul(a0, b2)
    a0 = gfP2Decode(a0)
    */
    t.Mul(bq, b)
    if t.x.Equal(zero) == 1 && t.y.Equal(one) == 1 {
        t.Mul(b2, a)
        x0.Sqrt(&t.y)
        t.MulScalar(bq, x0)
        ret.Set(t)
    } else {
        d, e, f := &gfP2{}, &gfP2{}, &gfP2{}
        d = d.expPMinus1Over2(c)
        e.Mul(d, c)
        f.Square(e)
        e.Invert(e)
        t.Mul(b2, a)
        t.Mul(t, f)
        x0.Sqrt(&t.y)
        t.MulScalar(bq, x0)
        t.Mul(t, e)
        ret.Set(t)
    }
    return ret
}
