package sm9curve

import (
    "math/big"
    "crypto/subtle"
)

// twistPoint implements the elliptic curve y²=x³+5/ξ (y²=x³+5i) over GF(p²). Points are
// kept in Jacobian form and t=z² when valid. The group G₂ is the set of
// n-torsion points of this curve over GF(p²) (where n = Order)
type twistPoint struct {
    x, y, z, t gfP2
}

var twistB = &gfP2{
    *newGFp(5),
    *zero,
}

// twistGen is the generator of group G₂.
var twistGen = &twistPoint{
    gfP2{
        *fromBigInt(bigFromHex("85AEF3D078640C98597B6027B441A01FF1DD2C190F5E93C454806C11D8806141")),
        *fromBigInt(bigFromHex("3722755292130B08D2AAB97FD34EC120EE265948D19C17ABF9B7213BAF82D65B")),
    },
    gfP2{
        *fromBigInt(bigFromHex("17509B092E845C1266BA0D262CBEE6ED0736A96FA347C8BD856DC76B84EBEB96")),
        *fromBigInt(bigFromHex("A7CF28D519BE3DA65F3170153D278FF247EFBA98A71A08116215BBA5C999A7C7")),
    },
    gfP2{*newGFp(0), *newGFp(1)},
    gfP2{*newGFp(0), *newGFp(1)},
}

func (c *twistPoint) String() string {
    c.MakeAffine()
    x, y := gfP2Decode(&c.x), gfP2Decode(&c.y)
    return "(" + x.String() + ", " + y.String() + ")"
}

func (c *twistPoint) Set(a *twistPoint) {
    c.x.Set(&a.x)
    c.y.Set(&a.y)
    c.z.Set(&a.z)
    c.t.Set(&a.t)
}

func NewTwistPoint() *twistPoint {
    c := &twistPoint{}
    c.SetInfinity()
    return c
}

func NewTwistGenerator() *twistPoint {
    c := &twistPoint{}
    c.Set(twistGen)
    return c
}

func (c *twistPoint) polynomial(x *gfP2) *gfP2 {
    x3 := &gfP2{}
    x3.Square(x).Mul(x3, x).Add(x3, twistB)
    return x3
}

// IsOnCurve returns true iff c is on the curve.
func (c *twistPoint) IsOnCurve() bool {
    c.MakeAffine()
    if c.IsInfinity() {
        return true
    }

    y2 := &gfP2{}
    y2.Square(&c.y)
    x3 := c.polynomial(&c.x)

    return *y2 == *x3
}

func (c *twistPoint) SetInfinity() {
    c.x.SetZero()
    c.y.SetOne()
    c.z.SetZero()
    c.t.SetZero()
}

func (c *twistPoint) IsInfinity() bool {
    return c.z.IsZero()
}

func (e *twistPoint) Equal(t *twistPoint) bool {
    return (&e.x).Equal(&t.x) &&
        (&e.y).Equal(&t.y) &&
        (&e.z).Equal(&t.z) &&
        (&e.t).Equal(&t.t)
}

func (c *twistPoint) Add(a, b *twistPoint) {
    // For additional comments, see the same function in curve.go.

    if a.IsInfinity() {
        c.Set(b)
        return
    }
    if b.IsInfinity() {
        c.Set(a)
        return
    }

    // See http://hyperelliptic.org/EFD/g1p/auto-code/shortw/jacobian-0/addition/add-2007-bl.op3
    z12 := (&gfP2{}).Square(&a.z)
    z22 := (&gfP2{}).Square(&b.z)
    u1 := (&gfP2{}).Mul(&a.x, z22)
    u2 := (&gfP2{}).Mul(&b.x, z12)

    t := (&gfP2{}).Mul(&b.z, z22)
    s1 := (&gfP2{}).Mul(&a.y, t)

    t.Mul(&a.z, z12)
    s2 := (&gfP2{}).Mul(&b.y, t)

    h := (&gfP2{}).Sub(u2, u1)
    xEqual := h.IsZero()

    t.Add(h, h)
    i := (&gfP2{}).Square(t)
    j := (&gfP2{}).Mul(h, i)

    t.Sub(s2, s1)
    yEqual := t.IsZero()
    if xEqual && yEqual {
        c.Double(a)
        return
    }
    r := (&gfP2{}).Add(t, t)

    v := (&gfP2{}).Mul(u1, i)

    t4 := (&gfP2{}).Square(r)
    t.Add(v, v)
    t6 := (&gfP2{}).Sub(t4, j)
    c.x.Sub(t6, t)

    t.Sub(v, &c.x) // t7
    t4.Mul(s1, j)  // t8
    t6.Add(t4, t4) // t9
    t4.Mul(r, t)   // t10
    c.y.Sub(t4, t6)

    t.Add(&a.z, &b.z) // t11
    t4.Square(t)      // t12
    t.Sub(t4, z12)    // t13
    t4.Sub(t, z22)    // t14
    c.z.Mul(t4, h)
}

func (c *twistPoint) Double(a *twistPoint) {
    // See http://hyperelliptic.org/EFD/g1p/auto-code/shortw/jacobian-0/doubling/dbl-2009-l.op3
    A := (&gfP2{}).Square(&a.x)
    B := (&gfP2{}).Square(&a.y)
    C := (&gfP2{}).Square(B)

    t := (&gfP2{}).Add(&a.x, B)
    t2 := (&gfP2{}).Square(t)
    t.Sub(t2, A)
    t2.Sub(t, C)
    d := (&gfP2{}).Add(t2, t2)
    t.Add(A, A)
    e := (&gfP2{}).Add(t, A)
    f := (&gfP2{}).Square(e)

    t.Add(d, d)
    c.x.Sub(f, t)

    c.z.Mul(&a.y, &a.z)
    c.z.Add(&c.z, &c.z)

    t.Add(C, C)
    t2.Add(t, t)
    t.Add(t2, t2)
    c.y.Sub(d, &c.x)
    t2.Mul(e, &c.y)
    c.y.Sub(t2, t)
}

func (c *twistPoint) Mul(a *twistPoint, scalar *big.Int) {
    sum, t := &twistPoint{}, &twistPoint{}

    for i := scalar.BitLen(); i >= 0; i-- {
        t.Double(sum)
        if scalar.Bit(i) != 0 {
            sum.Add(t, a)
        } else {
            sum.Set(t)
        }
    }

    c.Set(sum)
}

func (c *twistPoint) MakeAffine() {
    if c.z.IsOne() {
        return
    } else if c.z.IsZero() {
        c.x.SetZero()
        c.y.SetOne()
        c.t.SetZero()
        return
    }

    zInv := (&gfP2{}).Invert(&c.z)
    t := (&gfP2{}).Mul(&c.y, zInv)
    zInv2 := (&gfP2{}).Square(zInv)
    c.y.Mul(t, zInv2)
    t.Mul(&c.x, zInv2)
    c.x.Set(t)
    c.z.SetOne()
    c.t.SetOne()
}

func (c *twistPoint) Neg(a *twistPoint) {
    c.x.Set(&a.x)
    c.y.Neg(&a.y)
    c.z.Set(&a.z)
    c.t.SetZero()
}

// code logic is form https://github.com/guanzhi/GmSSL/blob/develop/src/sm9_alg.c
// the value is not same as [p]a
func (c *twistPoint) Frobenius(a *twistPoint) {
    c.x.Conjugate(&a.x)
    c.y.Conjugate(&a.y)
    c.z.Conjugate(&a.z)
    c.z.MulScalar(&a.z, frobConstant)
    c.t.Square(&a.z)
}

func (c *twistPoint) FrobeniusP2(a *twistPoint) {
    c.x.Set(&a.x)
    c.y.Set(&a.y)
    c.z.MulScalar(&a.z, wToP2Minus1)
    c.t.Square(&a.z)
}

func (c *twistPoint) NegFrobeniusP2(a *twistPoint) {
    c.x.Set(&a.x)
    c.y.Neg(&a.y)
    c.z.MulScalar(&a.z, wToP2Minus1)
    c.t.Square(&a.z)
}

// Select sets q to p1 if cond == 1, and to p2 if cond == 0.
func (q *twistPoint) Select(p1, p2 *twistPoint, cond int) *twistPoint {
    q.x.Select(&p1.x, &p2.x, cond)
    q.y.Select(&p1.y, &p2.y, cond)
    q.z.Select(&p1.z, &p2.z, cond)
    q.t.Select(&p1.t, &p2.t, cond)
    return q
}

// A twistPointTable holds the first 15 multiples of a point at offset -1, so [1]P
// is at table[0], [15]P is at table[14], and [0]P is implicitly the identity
// point.
type twistPointTable [15]*twistPoint

// Select selects the n-th multiple of the table base point into p. It works in
// constant time by iterating over every entry of the table. n must be in [0, 15].
func (table *twistPointTable) Select(p *twistPoint, n uint8) {
    if n >= 16 {
        panic("sm9: internal error: twistPointTable called with out-of-bounds value")
    }
    p.SetInfinity()
    for i, f := range table {
        cond := subtle.ConstantTimeByteEq(uint8(i+1), n)
        p.Select(f, p, cond)
    }
}
