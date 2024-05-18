package gost

import (
    "errors"
    "math/big"
)

var (
    zero    *big.Int = big.NewInt(0)
    bigInt1 *big.Int = big.NewInt(1)
    bigInt2 *big.Int = big.NewInt(2)
    bigInt3 *big.Int = big.NewInt(3)
    bigInt4 *big.Int = big.NewInt(4)
)

type Curve struct {
    Name string

    // Characteristic of the underlying prime field
    P *big.Int
    // Elliptic curve subgroup order
    Q *big.Int

    // Cofactor
    Co *big.Int

    // Equation coefficients of the elliptic curve in canonical form
    A *big.Int
    B *big.Int

    // Equation coefficients of the elliptic curve in twisted Edwards form
    E *big.Int
    D *big.Int

    // Basic point X and Y coordinates
    X *big.Int
    Y *big.Int

    // Cached s/t parameters for Edwards curve points conversion
    edS *big.Int
    edT *big.Int
}

func NewCurve(p, q, a, b, x, y, e, d, co *big.Int) (*Curve, error) {
    c := Curve{
        Name: "unknown",
        P:    p,
        Q:    q,
        A:    a,
        B:    b,
        X:    x,
        Y:    y,
    }
    if !c.IsOnCurve(c.X, c.Y) {
        return nil, errors.New("cryptobin/gost: invalid curve parameters")
    }

    if e != nil && d != nil {
        c.E = e
        c.D = d
    }

    if co == nil {
        c.Co = bigInt1
    } else {
        c.Co = co
    }

    return &c, nil
}

// Contains
func (c *Curve) IsOnCurve(x, y *big.Int) bool {
    r1 := big.NewInt(0)
    r2 := big.NewInt(0)
    r1.Mul(y, y)
    r1.Mod(r1, c.P)
    r2.Mul(x, x)
    r2.Add(r2, c.A)
    r2.Mul(r2, x)
    r2.Add(r2, c.B)
    r2.Mod(r2, c.P)
    c.pos(r2)
    return r1.Cmp(r2) == 0
}

// Get the size of the point's coordinate in bytes.
// 32 for 256-bit curves, 64 for 512-bit ones.
func (c *Curve) PointSize() int {
    if c.P.BitLen() > 256 {
        return 64
    }

    return 32
}

func (c *Curve) Params() *Curve {
    return c
}

func (c *Curve) pos(v *big.Int) {
    if v.Cmp(zero) < 0 {
        v.Add(v, c.P)
    }
}

func (c *Curve) add(p1x, p1y, p2x, p2y *big.Int) {
    var t, tx, ty big.Int
    if p1x.Cmp(p2x) == 0 && p1y.Cmp(p2y) == 0 {
        // double
        t.Mul(p1x, p1x)
        t.Mul(&t, bigInt3)
        t.Add(&t, c.A)
        tx.Mul(bigInt2, p1y)
        tx.ModInverse(&tx, c.P)
        t.Mul(&t, &tx)
        t.Mod(&t, c.P)
    } else {
        tx.Sub(p2x, p1x)
        tx.Mod(&tx, c.P)
        c.pos(&tx)
        ty.Sub(p2y, p1y)
        ty.Mod(&ty, c.P)
        c.pos(&ty)
        t.ModInverse(&tx, c.P)
        t.Mul(&t, &ty)
        t.Mod(&t, c.P)
    }

    tx.Mul(&t, &t)
    tx.Sub(&tx, p1x)
    tx.Sub(&tx, p2x)
    tx.Mod(&tx, c.P)
    c.pos(&tx)

    ty.Sub(p1x, &tx)
    ty.Mul(&ty, &t)
    ty.Sub(&ty, p1y)
    ty.Mod(&ty, c.P)
    c.pos(&ty)

    p1x.Set(&tx)
    p1y.Set(&ty)
}

func (c *Curve) Add(x1, y1, x2, y2 *big.Int) (*big.Int, *big.Int) {
    var px, py big.Int

    px.Set(x1)
    py.Set(y1)

    c.add(&px, &py, x2, y2)

    return &px, &py
}

func (c *Curve) Double(p1x, p1y *big.Int) (x *big.Int, y *big.Int) {
    var t, tx big.Int

    t.Mul(p1x, p1x)
    t.Mul(&t, bigInt3)
    t.Add(&t, c.A)
    tx.Mul(bigInt2, p1y)
    tx.ModInverse(&tx, c.P)
    t.Mul(&t, &tx)
    t.Mod(&t, c.P)

    return &t, &tx
}

func (c *Curve) ScalarMult(x1, y1 *big.Int, key []byte) (x *big.Int, y *big.Int) {
    k := bigIntFromBytes(key)
    if k.Cmp(zero) == 0 {
        panic("cryptobin/gost: zero key")
    }

    k = k.Mod(k, c.Q)

    x, y, err := c.Exp(k, x1, y1)
    if err != nil {
        panic("cryptobin/gost: ScalarMult was called on an invalid point")
    }

    return
}

func (c *Curve) ScalarBaseMult(key []byte) (x, y *big.Int) {
    k := bigIntFromBytes(key)
    if k.Cmp(zero) == 0 {
        panic("cryptobin/gost: zero key")
    }

    k = k.Mod(k, c.Q)

    x, y, err := c.Exp(k, c.X, c.Y)
    if err != nil {
        panic("cryptobin/gost: ScalarBaseMult was called on an invalid point")
    }

    return
}

func (c *Curve) Exp(degree, xS, yS *big.Int) (*big.Int, *big.Int, error) {
    if degree.Cmp(zero) == 0 {
        return nil, nil, errors.New("cryptobin/gost: zero degree value")
    }

    dg := big.NewInt(0).Sub(degree, bigInt1)
    tx := big.NewInt(0).Set(xS)
    ty := big.NewInt(0).Set(yS)
    cx := big.NewInt(0).Set(xS)
    cy := big.NewInt(0).Set(yS)

    for dg.Cmp(zero) != 0 {
        if dg.Bit(0) == 1 {
            c.add(tx, ty, cx, cy)
        }

        dg.Rsh(dg, 1)
        c.add(cx, cy, cx, cy)
    }

    return tx, ty, nil
}

func (c *Curve) Equal(x *Curve) bool {
    return c.P.Cmp(x.P) == 0 &&
        c.Q.Cmp(x.Q) == 0 &&
        c.A.Cmp(x.A) == 0 &&
        c.B.Cmp(x.B) == 0 &&
        c.X.Cmp(x.X) == 0 &&
        c.Y.Cmp(x.Y) == 0 &&
        ((c.E == nil && x.E == nil) || c.E.Cmp(x.E) == 0) &&
        ((c.D == nil && x.D == nil) || c.D.Cmp(x.D) == 0) &&
        c.Co.Cmp(x.Co) == 0
}

func (c *Curve) String() string {
    return c.Name
}

