package sm9curve

import (
    "math/big"
)

// twistPoint implements the elliptic curve y²=x³+5/ξ over GF(p²). Points are
// kept in Jacobian form and t=z² when valid. The group G₂ is the set of
// n-torsion points of this curve over GF(p²) (where n = Order)
type twistPoint struct {
    x, y, z, t gfP2
}

var twistB = &gfP2{
    *newGFp(5),
    *newGFp(0),
}

// twistGen is the generator of group G₂ (in form of montEncode).
var twistGen = &twistPoint{
    gfP2{
        gfP{0xdb6db4822750a8a6, 0x84c6135a5121f134, 0x1874032f88791d41, 0x905112f2b85f3a37},
        gfP{0x260226a68ce2da8f, 0x7ee5645edbf6c06b, 0xf8f57c82b1495444, 0x61fcf018bc47c4d1},
    },
    gfP2{
        gfP{0xf7b82dac4c89bfbb, 0x3706f3f6a49dc12f, 0x1e29de93d3eef769, 0x81e448c3c76a5d53},
        gfP{0xc03f138f9171c24a, 0x92fbab45a15a3ca7, 0x2445561e2ff77cdb, 0x108495e0c0f62ece},
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

// IsOnCurve returns true iff c is on the curve.
func (c *twistPoint) IsOnCurve() bool {
    c.MakeAffine()
    if c.IsInfinity() {
        return true
    }

    y2, x3 := &gfP2{}, &gfP2{}
    y2.Square(&c.y)
    x3.Square(&c.x).Mul(x3, &c.x).Add(x3, twistB)

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
