package rabin

import (
    "bytes"
    "fmt"
    "math/big"
)

// polyGF2 is a polynomial over GF(2).
type polyGF2 struct {
    coeff big.Int
}

// newPolyGF2 constructs a polyGF2 where the i'th coefficient is the
// i'th bit of coeffs.
func newPolyGF2(coeffs uint64) *polyGF2 {
    var p polyGF2
    p.coeff.SetUint64(coeffs)
    return &p
}

// Degree returns the degree of polynomial p. If p is 0, it returns
// -1.
func (z *polyGF2) Degree() int {
    return z.coeff.BitLen() - 1
}

// MulX sets z to a(x) * x^n and returns z.
func (z *polyGF2) MulX(a *polyGF2, n int) *polyGF2 {
    if n < 0 {
        panic("power must be >= 0")
    }
    z.coeff.Lsh(&a.coeff, uint(n))
    return z
}

// Add sets z to a(x) + b(x) and returns z.
func (z *polyGF2) Add(a, b *polyGF2) *polyGF2 {
    z.coeff.Xor(&a.coeff, &b.coeff)
    return z
}

// Sub sets z to a(x) - b(x) and returns z.
func (z *polyGF2) Sub(a, b *polyGF2) *polyGF2 {
    return z.Add(a, b)
}

// Mul sets z to a(x) * b(x) and returns z.
func (z *polyGF2) Mul(a, b *polyGF2) *polyGF2 {
    var out *polyGF2
    if z != a && z != b {
        out = z
    } else {
        out = &polyGF2{}
    }

    dx := a.Degree()
    var bs big.Int
    for i := 0; i <= dx; i++ {
        if a.coeff.Bit(i) != 0 {
            bs.Lsh(&b.coeff, uint(i))
            out.coeff.Xor(&out.coeff, &bs)
        }
    }

    if z != out {
        z.coeff.Set(&out.coeff)
    }
    return z
}

// Mod sets z to the remainder of a(x) / b(x) and returns z.
func (z *polyGF2) Mod(a, b *polyGF2) *polyGF2 {
    var out *polyGF2
    if z != a && z != b {
        out = z
    } else {
        out = &polyGF2{}
    }

    // Compute the remainder using synthetic division.
    da, db := a.Degree(), b.Degree()
    if db < 0 {
        panic("divide by zero")
    }
    out.coeff.Set(&a.coeff)
    var tmp polyGF2
    for i := da - db; i >= 0; i-- {
        if out.coeff.Bit(i+db) != 0 {
            tmp.MulX(b, i)
            out.Sub(out, &tmp)
        }
    }

    if z != out {
        z.coeff.Set(&out.coeff)
    }
    return z
}

// String returns p represented in mathematical notation.
func (z *polyGF2) String() string {
    if z.coeff.Sign() == 0 {
        return "0"
    }
    var s bytes.Buffer
    for i := z.Degree(); i >= 0; i-- {
        if z.coeff.Bit(i) == 0 {
            continue
        }
        if s.Len() > 0 {
            s.WriteByte('+')
        }
        switch {
        case i == 0:
            s.WriteByte('1')
        case i == 1:
            s.WriteByte('x')
        default:
            fmt.Fprintf(&s, "x^%d", i)
        }
    }
    return s.String()
}
