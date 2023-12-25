package sm9curve

import "math/big"

// gfP12b6 implements the field of size p¹² as a quadratic extension of gfP6
// where t²=s.
type gfP12 struct {
    x, y gfP6 // value is xt + y
}

func gfP12Decode(in *gfP12) *gfP12 {
    out := &gfP12{}
    out.x = *gfP6Decode(&in.x)
    out.y = *gfP6Decode(&in.y)
    return out
}

var gfP12Gen *gfP12 = &gfP12{
    x: gfP6{
        x: gfP2{
            x: *fromBigInt(bigFromHex("256943fbdb2bf87ab91ae7fbeaff14e146cf7e2279b9d155d13461e09b22f523")),
            y: *fromBigInt(bigFromHex("0167b0280051495c6af1ec23ba2cd2ff1cdcdeca461a5ab0b5449e9091308310")),
        },
        y: gfP2{
            x: *fromBigInt(bigFromHex("8ffe1c0e9de45fd0fed790ac26be91f6b3f0a49c084fe29a3fb6ed288ad7994d")),
            y: *fromBigInt(bigFromHex("1664a1366beb3196f0443e15f5f9042a947354a5678430d45ba031cff06db927")),
        },
        z: gfP2{
            x: *fromBigInt(bigFromHex("7fc6eb2aa771d99c9234fddd31752edfd60723e05a4ebfdeb5c33fbd47e0cf06")),
            y: *fromBigInt(bigFromHex("6fa6b6fa6dd6b6d3b19a959a110e748154eef796dc0fc2dd766ea414de786968")),
        },
    },
    y: gfP6{
        x: gfP2{
            x: *fromBigInt(bigFromHex("082cde173022da8cd09b28a2d80a8cee53894436a52007f978dc37f36116d39b")),
            y: *fromBigInt(bigFromHex("3fa7ed741eaed99a58f53e3df82df7ccd3407bcc7b1d44a9441920ced5fb824f")),
        },
        y: gfP2{
            x: *fromBigInt(bigFromHex("5e7addaddf7fbfe16291b4e89af50b8217ddc47ba3cba833c6e77c3fb027685e")),
            y: *fromBigInt(bigFromHex("79d0c8337072c93fef482bb055f44d6247ccac8e8e12525854b3566236337ebe")),
        },
        z: gfP2{
            x: *fromBigInt(bigFromHex("7f7c6d52b475e6aaa827fdc5b4175ac6929320f782d998f86b6b57cda42a0426")),
            y: *fromBigInt(bigFromHex("36a699de7c136f78eee2dbac4ca9727bff0cee02ee920f5822e65ea170aa9669")),
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

func (e *gfP12) Equal(t *gfP12) bool {
    return (&e.x).Equal(&t.x) &&
        (&e.y).Equal(&t.y)
}

func (e *gfP12) Neg(a *gfP12) *gfP12 {
    e.x.Neg(&a.x)
    e.y.Neg(&a.y)
    return e
}

func (e *gfP12) Conjugate(a *gfP12) *gfP12 {
    e.x.Neg(&a.x)
    e.y.Set(&a.y)
    return e
}

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
    // "Multiplication and Squaring on Pairing-Friendly Fields"
    // Section 4, Karatsuba method.
    // http://eprint.iacr.org/2006/471.pdf
    //(a0+a1*t)(b0+b1*t)=c0+c1*t, where
    //c0 = a0*b0 +a1*b1*s
    //c1 = (a0 + a1)(b0 + b1) - a0*b0 - a1*b1 = a0*b1 + a1*b0
    tx, ty, v0, v1 := &gfP6{}, &gfP6{}, &gfP6{}, &gfP6{}
    v0.Mul(&a.y, &b.y)
    v1.Mul(&a.x, &b.x)

    tx.Add(&a.x, &a.y)
    ty.Add(&b.x, &b.y)
    tx.Mul(tx, ty)
    tx.Sub(tx, v0)
    tx.Sub(tx, v1)

    ty.MulS(v1)
    ty.Add(ty, v0)

    e.x.Set(tx)
    e.y.Set(ty)
    return e
}

func (e *gfP12) MulScalar(a *gfP12, b *gfP6) *gfP12 {
    e.x.Mul(&a.x, b)
    e.y.Mul(&a.y, b)
    return e
}

func (e *gfP12) MulGfP(a *gfP12, b *gfP) *gfP12 {
    e.x.MulGfP(&a.x, b)
    e.y.MulGfP(&a.y, b)
    return e
}

func (e *gfP12) MulGfP2(a *gfP12, b *gfP2) *gfP12 {
    e.x.MulScalar(&a.x, b)
    e.y.MulScalar(&a.y, b)
    return e
}

func (e *gfP12) Square(a *gfP12) *gfP12 {
    // Complex squaring algorithm
    // (xt+y)² = (x^2*s + y^2) + 2*x*y*t
    tx, ty := &gfP6{}, &gfP6{}
    tx.Square(&a.x).MulS(tx)
    ty.Square(&a.y)
    ty.Add(tx, ty)

    tx.Mul(&a.x, &a.y)
    tx.Add(tx, tx)

    e.x.Set(tx)
    e.y.Set(ty)
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

func (e *gfP12) Invert(a *gfP12) *gfP12 {
    // See "Implementing cryptographic pairings", M. Scott, section 3.2.
    // ftp://136.206.11.249/pub/crypto/pairings.pdf

    t0, t1 := &gfP6{}, &gfP6{}

    t0.Mul(&a.y, &a.y)
    t1.Mul(&a.x, &a.x).MulS(t1)
    t0.Sub(t0, t1)
    t0.Invert(t0)

    e.x.Neg(&a.x)
    e.y.Set(&a.y)
    e.MulScalar(e, t0)

    return e
}

// Frobenius computes (xt+y)^p
// = x^p t^p + y^p
// = x^p t^(p-1) t + y^p
// = x^p s^((p-1)/2) t + y^p
// sToPMinus1Over2
func (e *gfP12) Frobenius(a *gfP12) *gfP12 {
    e.x.Frobenius(&a.x)
    e.y.Frobenius(&a.y)
    e.x.MulGfP(&e.x, sToPMinus1Over2)
    return e
}

// FrobeniusP2 computes (xt+y)^p² = x^p² t ·s^((p²-1)/2) + y^p²
func (e *gfP12) FrobeniusP2(a *gfP12) *gfP12 {
    e.x.FrobeniusP2(&a.x)
    e.y.FrobeniusP2(&a.y)
    e.x.MulGfP(&e.x, sToPSquaredMinus1Over2)
    return e
}

func (e *gfP12) FrobeniusP4(a *gfP12) *gfP12 {
    e.x.FrobeniusP4(&a.x)
    e.y.FrobeniusP4(&a.y)
    e.x.MulGfP(&e.x, sToPSquaredMinus1)
    return e
}

func (e *gfP12) FrobeniusP6(a *gfP12) *gfP12 {
    e.x.Neg(&a.x)
    e.y.Set(&a.y)
    return e
}

// Select sets q to p1 if cond == 1, and to p2 if cond == 0.
func (q *gfP12) Select(p1, p2 *gfP12, cond int) *gfP12 {
    q.x.Select(&p1.x, &p2.x, cond)
    q.y.Select(&p1.y, &p2.y, cond)
    return q
}
