package edwards448

import (
    "errors"

    "github.com/deatil/go-cryptobin/elliptic/edwards448/field"
)

var feOne = new(field.Element).One()
var feD = new(field.Element).SetBytes([]byte{
    0x56, 0x67, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
})

// Point represents a point on the edwards25519 curve.
//
// This type works similarly to math/big.Int, and all arguments and receivers
// are allowed to alias.
//
// The zero value is NOT valid, and it may be used only as a receiver.
type Point struct {
    // The point is internally represented in extended coordinates (X, Y, Z)
    // where x = X/Z, y = Y/Z.
    x, y, z field.Element

    // Make the type not comparable (i.e. used with == or as a map key), as
    // equivalent points can be represented by different Go values.
    _ incomparable
}

type incomparable [0]func()

func checkInitialized(points ...*Point) {
    for _, p := range points {
        if p.x == (field.Element{}) && p.y == (field.Element{}) {
            panic("edwards25519: use of uninitialized Point")
        }
    }
}

// identity is the point at infinity.
var identity, _ = new(Point).SetBytes([]byte{
    1, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0,
})

// NewIdentityPoint returns a new Point set to the identity.
func NewIdentityPoint() *Point {
    return new(Point).Set(identity)
}

// generator is the canonical curve basepoint. See TestGenerator for the
// correspondence of this encoding with the values in RFC 8032.
var generator, _ = new(Point).SetBytes([]byte{
    0x14, 0xfa, 0x30, 0xf2, 0x5b, 0x79, 0x08, 0x98,
    0xad, 0xc8, 0xd7, 0x4e, 0x2c, 0x13, 0xbd, 0xfd,
    0xc4, 0x39, 0x7c, 0xe6, 0x1c, 0xff, 0xd3, 0x3a,
    0xd7, 0xc2, 0xa0, 0x05, 0x1e, 0x9c, 0x78, 0x87,
    0x40, 0x98, 0xa3, 0x6c, 0x73, 0x73, 0xea, 0x4b,
    0x62, 0xc7, 0xc9, 0x56, 0x37, 0x20, 0x76, 0x88,
    0x24, 0xbc, 0xb6, 0x6e, 0x71, 0x46, 0x3f, 0x69, 0x0,
})

// NewGeneratorPoint returns a new Point set to the canonical generator.
func NewGeneratorPoint() *Point {
    return new(Point).Set(generator)
}

// Set sets v = u, and returns v.
func (v *Point) Set(u *Point) *Point {
    *v = *u
    return v
}

func (v *Point) Zero() *Point {
    v.x.Zero()
    v.y.One()
    v.z.One()
    return v
}

// Encoding.

// Bytes returns the canonical 57-byte encoding of v, according to RFC 8032,
// Section 5.2.2.
func (v *Point) Bytes() []byte {
    // This function is outlined to make the allocations inline in the caller
    // rather than happen on the heap.
    var buf [57]byte
    return v.bytes(&buf)
}

func (v *Point) bytes(buf *[57]byte) []byte {
    checkInitialized(v)

    var zInv, x, y field.Element
    zInv.Inv(&v.z)     // zInv = 1 / Z
    x.Mul(&v.x, &zInv) // x = X / Z
    y.Mul(&v.y, &zInv) // y = Y / Z

    out := copyFieldElement(buf, &y)
    out[56] |= byte(x.IsNegative() << 7)
    return out
}

func (v *Point) SetBytes(data []byte) (*Point, error) {
    if len(data) != 57 {
        return nil, errors.New("edwards448: invalid point encoding length")
    }

    var y field.Element
    y.SetBytes(data[:56])

    // x² + y² = 1 + dx²y²
    // dx²y² - x² = x²(dy² - 1) = y² - 1
    // x² = (y² - 1) / (dy² - 1)

    // u = y² - 1
    var u, y2 field.Element
    y2.Square(&y)
    u.Sub(&y2, feOne)

    // v = dy² - 1
    var vv field.Element
    vv.Mul(&y2, feD)
    vv.Sub(&vv, feOne)

    // x = +√(u/v)
    var x field.Element
    _, wasSquare := x.SqrtRatio(&u, &vv)

    // Select the negative square root if the sign bit is set.
    var xNeg field.Element
    xNeg.Negate(&x)
    x.Select(&xNeg, &x, int(data[56]>>7)^x.IsNegative())

    if wasSquare == 0 {
        return nil, errors.New("edwards448: invalid point encoding")
    }

    v.x.Set(&x)
    v.y.Set(&y)
    v.z.One()
    return v, nil
}

// Conversions.

func copyFieldElement(buf *[57]byte, v *field.Element) []byte {
    copy(buf[:56], v.Bytes())
    return buf[:]
}

// Equal returns 1 if v is equivalent to u, and 0 otherwise.
func (v *Point) Equal(u *Point) int {
    checkInitialized(v, u)

    var x1, y1, x2, y2 field.Element
    x1.Mul(&v.x, &u.z)
    y1.Mul(&v.y, &u.z)
    x2.Mul(&u.x, &v.z)
    y2.Mul(&u.y, &v.z)
    return x1.Equal(&x2) & y1.Equal(&y2)
}

func (v *Point) Add(p, q *Point) *Point {
    checkInitialized(p, q)

    var a, b, c, d, e, f, g, h, x, y, z field.Element
    var tmp1, tmp2 field.Element

    // A = Z1*Z2
    a.Mul(&p.z, &q.z)

    // B = A^2
    b.Square(&a)

    // C = X1*X2
    c.Mul(&p.x, &q.x)

    // D = Y1*Y2
    d.Mul(&p.y, &q.y)

    // E = d*C*D
    tmp1.Mul(feD, &c)
    e.Mul(&tmp1, &d)

    // F = B-E
    f.Sub(&b, &e)

    // G = B+E
    g.Add(&b, &e)

    // H = (X1+Y1)*(X2+Y2)
    tmp1.Add(&p.x, &p.y)
    tmp2.Add(&q.x, &q.y)
    h.Mul(&tmp1, &tmp2)

    // X3 = A*F*(H-C-D)
    x.Sub(&h, &c)
    x.Sub(&x, &d)
    x.Mul(&x, &a)
    x.Mul(&x, &f)

    // Y3 = A*G*(D-C)
    y.Sub(&d, &c)
    y.Mul(&y, &g)
    y.Mul(&y, &a)

    // Z3 = F*G
    z.Mul(&f, &g)

    v.x.Set(&x)
    v.y.Set(&y)
    v.z.Set(&z)
    return v
}

func (v *Point) Double(u *Point) *Point {
    // B = (X1+Y1)^2
    var b field.Element
    b.Add(&u.x, &u.y)
    b.Square(&b)

    // C = X1^2
    var c field.Element
    c.Square(&u.x)

    // D = Y1^2
    var d field.Element
    d.Square(&u.y)

    // E = C+D
    var e field.Element
    e.Add(&c, &d)

    // H = Z1^2
    var h field.Element
    h.Square(&u.z)

    // J = E-2*H
    var j field.Element
    j.Add(&h, &h)
    j.Sub(&e, &j)

    // X3 = (B-E)*J
    var x field.Element
    x.Sub(&b, &e)
    x.Mul(&x, &j)

    // Y3 = E*(C-D)
    var y field.Element
    y.Sub(&c, &d)
    y.Mul(&e, &y)

    // Z3 = E*J
    var z field.Element
    z.Mul(&e, &j)

    v.x.Set(&x)
    v.y.Set(&y)
    v.z.Set(&z)
    return v
}

func (v *Point) Sub(p, q *Point) *Point {
    var neg Point
    neg.Negate(q)
    return v.Add(p, &neg)
}

func (v *Point) Select(p, q *Point, cond int) *Point {
    v.x.Select(&p.x, &q.x, cond)
    v.y.Select(&p.y, &q.y, cond)
    v.z.Select(&p.z, &q.z, cond)
    return v
}

// Negate sets v = -p, and returns v.
func (v *Point) Negate(p *Point) *Point {
    checkInitialized(p)
    v.x.Negate(&p.x)
    v.y.Set(&p.y)
    v.z.Set(&p.z)
    return v
}

func (v *Point) CondNeg(cond int) *Point {
    var neg Point
    neg.Negate(v)
    return v.Select(&neg, v, cond)
}
