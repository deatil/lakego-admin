package sm9curve

import "math/big"

// For details of the algorithms used, see "Multiplication and Squaring on
// Pairing-Friendly Fields, Devegili et al.
// http://eprint.iacr.org/2006/471.pdf.
//

// gfP6 implements the field of size p^6 as a cubic extension of gfP2
// where s³=ξ and ξ=u
type gfP6 struct {
    x, y, z gfP2 // value is xs² + ys + z
}

func gfP6Decode(in *gfP6) *gfP6 {
    out := &gfP6{}
    out.x = *gfP2Decode(&in.x)
    out.y = *gfP2Decode(&in.y)
    out.z = *gfP2Decode(&in.z)
    return out
}

func (e *gfP6) String() string {
    return "(" + e.x.String() + ", " + e.y.String() + ", " + e.z.String() + ")"
}

func (e *gfP6) Set(a *gfP6) *gfP6 {
    e.x.Set(&a.x)
    e.y.Set(&a.y)
    e.z.Set(&a.z)
    return e
}

func (e *gfP6) SetZero() *gfP6 {
    e.x.SetZero()
    e.y.SetZero()
    e.z.SetZero()
    return e
}

func (e *gfP6) SetOne() *gfP6 {
    e.x.SetZero()
    e.y.SetZero()
    e.z.SetOne()
    return e
}

func (e *gfP6) SetS() *gfP6 {
    e.x.SetZero()
    e.y.SetOne()
    e.z.SetZero()
    return e
}

func (e *gfP6) SetS2() *gfP6 {
    e.x.SetOne()
    e.y.SetZero()
    e.z.SetZero()
    return e
}

func (e *gfP6) IsZero() bool {
    return e.x.IsZero() && e.y.IsZero() && e.z.IsZero()
}

func (e *gfP6) IsOne() bool {
    return e.x.IsZero() && e.y.IsZero() && e.z.IsOne()
}

func (e *gfP6) Equal(t *gfP6) bool {
    return (&e.x).Equal(&t.x) &&
        (&e.y).Equal(&t.y) &&
        (&e.z).Equal(&t.z)
}

func (e *gfP6) Neg(a *gfP6) *gfP6 {
    e.x.Neg(&a.x)
    e.y.Neg(&a.y)
    e.z.Neg(&a.z)
    return e
}

func (e *gfP6) Add(a, b *gfP6) *gfP6 {
    e.x.Add(&a.x, &b.x)
    e.y.Add(&a.y, &b.y)
    e.z.Add(&a.z, &b.z)
    return e
}

func (e *gfP6) Sub(a, b *gfP6) *gfP6 {
    e.x.Sub(&a.x, &b.x)
    e.y.Sub(&a.y, &b.y)
    e.z.Sub(&a.z, &b.z)
    return e
}

func (e *gfP6) MulScalar(a *gfP6, b *gfP2) *gfP6 {
    e.x.Mul(&a.x, b)
    e.y.Mul(&a.y, b)
    e.z.Mul(&a.z, b)
    return e
}

func (e *gfP6) MulGfP(a *gfP6, b *gfP) *gfP6 {
    e.x.MulScalar(&a.x, b)
    e.y.MulScalar(&a.y, b)
    e.z.MulScalar(&a.z, b)
    return e
}

func (e *gfP6) Mul(a, b *gfP6) *gfP6 {
    // (z0 + y0*s + x0*s²)* (z1 + y1*s + x1*s²)
    //  z0*z1 + z0*y1*s + z0*x1*s²
    // +y0*z1*s + y0*y1*s² + y0*x1*u
    // +x0*z1*s² + x0*y1*u + x0*x1*s*u
    //=(z0*z1+y0*x1*u+x0*y1*u) + (z0*y1+y0*z1+x0*x1*u)s + (z0*x1 + y0*y1 + x0*z1)*s²
    tx, ty, tz, t, v0, v1, v2 := &gfP2{}, &gfP2{}, &gfP2{}, &gfP2{}, &gfP2{}, &gfP2{}, &gfP2{}
    v0.Mul(&a.z, &b.z)
    v1.Mul(&a.y, &b.y)
    v2.Mul(&a.x, &b.x)

    t.Add(&a.y, &a.x)
    tz.Add(&b.y, &b.x)
    t.Mul(t, tz)
    t.Sub(t, v1)
    t.Sub(t, v2)
    t.MulU1(t)
    tz.Add(t, v0)

    t.Add(&a.z, &a.y)
    ty.Add(&b.z, &b.y)
    ty.Mul(t, ty)
    ty.Sub(ty, v0)
    ty.Sub(ty, v1)
    t.MulU1(v2)
    ty.Add(ty, t)

    t.Add(&a.z, &a.x)
    tx.Add(&b.z, &b.x)
    tx.Mul(tx, t)
    tx.Sub(tx, v0)
    tx.Add(tx, v1)
    tx.Sub(tx, v2)

    e.x.Set(tx)
    e.y.Set(ty)
    e.z.Set(tz)
    return e
}

// MulS returns (z + y*s + x*s²)*s
// = ys² + zs + xu
func (e *gfP6) MulS(a *gfP6) *gfP6 {
    ty := (&gfP2{}).Set(&a.y)
    tz := &gfP2{}

    tz.x.Set(&a.x.y)
    gfpAdd(&tz.y, &a.x.x, &a.x.x)
    gfpNeg(&tz.y, &tz.y)

    e.y.Set(&a.z)
    e.x.Set(ty)
    e.z.Set(tz)

    return e
}

func (e *gfP6) Square(a *gfP6) *gfP6 {
    // (z + y*s + x*s²)* (z + y*s + x*s²)
    // z^2 + z*y*s + z*x*s² + y*z*s + y^2*s² + y*x*u + x*z*s² + x*y*u + x^2 *u *s
    // (z^2 + y*x*s + x*y*u) + (z*y + y*z + u * x^2)s + (z*x + y^2 + x*z)*s²
    // (z^2 + 2*x*y*u) + (u*x^2 + 2*y*z) * s + (y^2 + 2*x*z) * s²
    tx, ty, tz, t := &gfP2{}, &gfP2{}, &gfP2{}, &gfP2{}

    tz.Square(&a.z)
    t.MulU(&a.x, &a.y)
    t.Add(t, t)
    tz.Add(tz, t)

    ty.SquareU(&a.x)
    t.Mul(&a.y, &a.z)
    t.Add(t, t)
    ty.Add(ty, t)

    tx.Square(&a.y)
    t.Mul(&a.x, &a.z)
    t.Add(t, t)
    tx.Add(tx, t)

    e.x.Set(tx)
    e.y.Set(ty)
    e.z.Set(tz)
    return e
}

func (e *gfP6) Exp(f *gfP6, power *big.Int) *gfP6 {
    sum := (&gfP6{}).SetOne()
    t := &gfP6{}

    for i := power.BitLen() - 1; i >= 0; i-- {
        t.Square(sum)
        if power.Bit(i) != 0 {
            sum.Mul(t, f)
        } else {
            sum.Set(t)
        }
    }

    e.Set(sum)
    return e
}

func (e *gfP6) Invert(a *gfP6) *gfP6 {
    // See "Implementing cryptographic pairings", M. Scott, section 3.2.
    // ftp://136.206.11.249/pub/crypto/pairings.pdf

    t1 := (&gfP2{}).MulU(&a.x, &a.y)
    A := (&gfP2{}).Square(&a.z)
    A.Sub(A, t1)

    B := (&gfP2{}).SquareU(&a.x)
    t1.Mul(&a.y, &a.z)
    B.Sub(B, t1)

    C := (&gfP2{}).Square(&a.y)
    t1.Mul(&a.x, &a.z)
    C.Sub(C, t1)

    F := (&gfP2{}).MulU(C, &a.y)
    t1.Mul(A, &a.z)
    F.Add(F, t1)
    t1.MulU(B, &a.x)
    F.Add(F, t1)

    F.Invert(F)

    e.x.Mul(C, F)
    e.y.Mul(B, F)
    e.z.Mul(A, F)
    return e
}

// (z + y*s + x*s²)^p
//= z^p + y^p*s*s^(p-1)+x^p*s²*(s²)^(p-1)
//= z^p + (s^(p-1)*y^p)*s+((s²)^(p-1)*x^p)*s²
//= f(z) + (s^(p-1)*f(y))*s+((s²)^(p-1)*f(x))*s²
// sToPMinus1^3 = p - 1
// sTo2PMinus2 = sToPMinus1 ^ 2
func (e *gfP6) Frobenius(a *gfP6) *gfP6 {
    e.z.Conjugate(&a.z)
    e.y.Conjugate(&a.y)
    e.x.Conjugate(&a.x)
    e.y.MulScalar(&e.y, sToPMinus1)
    e.x.MulScalar(&e.x, sTo2PMinus2)

    return e
}

// FrobeniusP2 computes (xs²+ys+z)^(p²)
// = z^p² + y^p²*s^p² + x^p²*s²^p²
// = z + y*s^p² + x * s^(2p²)
// = z + y*s*s^(p²-1) + x * s² * s^(2p² - 2)
// = z + y*s*u^((p²-1)/3) + x * s² * u^((2p² - 2)/3)
// uToPSquaredMinus1Over3 = sToPSquaredMinus1
// s^(p²-1) = s^((p-1)(p+1)) = (s^(p-1))^(p+1) = sTo2PMinus2
//
// uToPSquaredMinus1Over3 = sTo2PSquaredMinus2
// = sTo2PMinus2^2
func (e *gfP6) FrobeniusP2(a *gfP6) *gfP6 {
    e.x.MulScalar(&a.x, sTo2PSquaredMinus2)
    e.y.MulScalar(&a.y, sToPSquaredMinus1)
    e.z.Set(&a.z)
    return e
}

// FrobeniusP4 computes (xs²+ys+z)^(p^4)
func (e *gfP6) FrobeniusP4(a *gfP6) *gfP6 {
    e.x.MulScalar(&a.x, sToPSquaredMinus1)
    e.y.MulScalar(&a.y, sTo2PSquaredMinus2)
    e.z.Set(&a.z)
    return e
}

// Select sets q to p1 if cond == 1, and to p2 if cond == 0.
func (q *gfP6) Select(p1, p2 *gfP6, cond int) *gfP6 {
    q.x.Select(&p1.x, &p2.x, cond)
    q.y.Select(&p1.y, &p2.y, cond)
    q.z.Select(&p1.z, &p2.z, cond)
    return q
}
