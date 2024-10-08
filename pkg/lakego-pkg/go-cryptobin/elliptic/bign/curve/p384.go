package bign

import (
    "crypto/subtle"
    "errors"
    "sync"

    "github.com/deatil/go-cryptobin/elliptic/bign/curve/fiat"
)

// p384ElementLength is the length of an element of the base or scalar field,
// which have the same bytes length for all NIST P curves.
const p384ElementLength = 48

// P384Point is a P384 point. The zero value is NOT valid.
type P384Point struct {
    // The point is represented in projective coordinates (X:Y:Z),
    // where x = X/Z and y = Y/Z.
    x, y, z *fiat.P384Element
}

// NewP384Point returns a new P384Point representing the point at infinity point.
func NewP384Point() *P384Point {
    return &P384Point{
        x: new(fiat.P384Element),
        y: new(fiat.P384Element).One(),
        z: new(fiat.P384Element),
    }
}

// SetGenerator sets p to the canonical generator and returns p.
func (p *P384Point) SetGenerator() *P384Point {
    p.x.SetBytes([]byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0})
    p.y.SetBytes([]byte{0x5d, 0x43, 0x82, 0x24, 0xa8, 0x2e, 0x9e, 0x9e, 0x63, 0x30, 0x11, 0x7e, 0x43, 0x2d, 0xbf, 0x89, 0x3a, 0x72, 0x9a, 0x11, 0xdc, 0x86, 0xff, 0xa0, 0x5, 0x49, 0xe7, 0x9e, 0x66, 0xb1, 0xd3, 0x55, 0x84, 0x40, 0x3e, 0x27, 0x6b, 0x2a, 0x42, 0xf9, 0xea, 0x5e, 0xcb, 0x31, 0xf7, 0x33, 0xc4, 0x51})
    p.z.One()
    return p
}

// Set sets p = q and returns p.
func (p *P384Point) Set(q *P384Point) *P384Point {
    p.x.Set(q.x)
    p.y.Set(q.y)
    p.z.Set(q.z)
    return p
}

// SetBytes sets p to the compressed, uncompressed, or infinity value encoded in
// b, as specified in SEC 1, Version 2.0, Section 2.3.4. If the point is not on
// the curve, it returns nil and an error, and the receiver is unchanged.
// Otherwise, it returns p.
func (p *P384Point) SetBytes(b []byte) (*P384Point, error) {
    switch {
    // Point at infinity.
    case len(b) == 1 && b[0] == 0:
        return p.Set(NewP384Point()), nil
    // Uncompressed form.
    case len(b) == 1+2*p384ElementLength && b[0] == 4:
        x, err := new(fiat.P384Element).SetBytes(b[1 : 1+p384ElementLength])
        if err != nil {
            return nil, err
        }
        y, err := new(fiat.P384Element).SetBytes(b[1+p384ElementLength:])
        if err != nil {
            return nil, err
        }
        if err := p384CheckOnCurve(x, y); err != nil {
            return nil, err
        }
        p.x.Set(x)
        p.y.Set(y)
        p.z.One()
        return p, nil
    // Compressed form.
    case len(b) == 1+p384ElementLength && (b[0] == 2 || b[0] == 3):
        x, err := new(fiat.P384Element).SetBytes(b[1:])
        if err != nil {
            return nil, err
        }
        // y² = x³ - 3x + b
        y := p384Polynomial(new(fiat.P384Element), x)
        if !p384Sqrt(y, y) {
            return nil, errors.New("invalid P384 compressed point encoding")
        }
        // Select the positive or negative root, as indicated by the least
        // significant bit, based on the encoding type byte.
        otherRoot := new(fiat.P384Element)
        otherRoot.Sub(otherRoot, y)
        cond := y.Bytes()[p384ElementLength-1]&1 ^ b[0]&1
        y.Select(otherRoot, y, int(cond))
        p.x.Set(x)
        p.y.Set(y)
        p.z.One()
        return p, nil
    default:
        return nil, errors.New("invalid P384 point encoding")
    }
}

var _p384B *fiat.P384Element
var _p384BOnce sync.Once

func p384B() *fiat.P384Element {
    _p384BOnce.Do(func() {
        _p384B, _ = new(fiat.P384Element).SetBytes([]byte{0x3c, 0x75, 0xdf, 0xe1, 0x95, 0x9c, 0xef, 0x20, 0x33, 0x7, 0x5a, 0xab, 0x65, 0x5d, 0x34, 0xd2, 0x71, 0x27, 0x48, 0xbb, 0xf, 0xfb, 0xb1, 0x96, 0xa6, 0x21, 0x6a, 0xf9, 0xe9, 0x71, 0x2e, 0x3a, 0x14, 0xbd, 0xe2, 0xf0, 0xf3, 0xce, 0xbd, 0x7c, 0xbc, 0xa7, 0xfc, 0x23, 0x68, 0x73, 0xbf, 0x64})
    })
    return _p384B
}

// p384Polynomial sets y2 to x³ - 3x + b, and returns y2.
func p384Polynomial(y2, x *fiat.P384Element) *fiat.P384Element {
    y2.Square(x)
    y2.Mul(y2, x)

    threeX := new(fiat.P384Element).Add(x, x)
    threeX.Add(threeX, x)

    y2.Sub(y2, threeX)

    return y2.Add(y2, p384B())
}

func p384CheckOnCurve(x, y *fiat.P384Element) error {
    // y² = x³ - 3x + b
    rhs := p384Polynomial(new(fiat.P384Element), x)
    lhs := new(fiat.P384Element).Square(y)
    if rhs.Equal(lhs) != 1 {
        return errors.New("P384 point not on curve")
    }
    return nil
}

// Bytes returns the uncompressed or infinity encoding of p, as specified in
// SEC 1, Version 2.0, Section 2.3.3. Note that the encoding of the point at
// infinity is shorter than all other encodings.
func (p *P384Point) Bytes() []byte {
    // This function is outlined to make the allocations inline in the caller
    // rather than happen on the heap.
    var out [1 + 2*p384ElementLength]byte
    return p.bytes(&out)
}

func (p *P384Point) bytes(out *[1 + 2*p384ElementLength]byte) []byte {
    if p.z.IsZero() == 1 {
        return append(out[:0], 0)
    }
    zinv := new(fiat.P384Element).Invert(p.z)
    x := new(fiat.P384Element).Mul(p.x, zinv)
    y := new(fiat.P384Element).Mul(p.y, zinv)
    buf := append(out[:0], 4)
    buf = append(buf, x.Bytes()...)
    buf = append(buf, y.Bytes()...)
    return buf
}

// BytesX returns the encoding of the x-coordinate of p, as specified in SEC 1,
// Version 2.0, Section 2.3.5, or an error if p is the point at infinity.
func (p *P384Point) BytesX() ([]byte, error) {
    // This function is outlined to make the allocations inline in the caller
    // rather than happen on the heap.
    var out [p384ElementLength]byte
    return p.bytesX(&out)
}

func (p *P384Point) bytesX(out *[p384ElementLength]byte) ([]byte, error) {
    if p.z.IsZero() == 1 {
        return nil, errors.New("P384 point is the point at infinity")
    }
    zinv := new(fiat.P384Element).Invert(p.z)
    x := new(fiat.P384Element).Mul(p.x, zinv)
    return append(out[:0], x.Bytes()...), nil
}

// BytesCompressed returns the compressed or infinity encoding of p, as
// specified in SEC 1, Version 2.0, Section 2.3.3. Note that the encoding of the
// point at infinity is shorter than all other encodings.
func (p *P384Point) BytesCompressed() []byte {
    // This function is outlined to make the allocations inline in the caller
    // rather than happen on the heap.
    var out [1 + p384ElementLength]byte
    return p.bytesCompressed(&out)
}

func (p *P384Point) bytesCompressed(out *[1 + p384ElementLength]byte) []byte {
    if p.z.IsZero() == 1 {
        return append(out[:0], 0)
    }
    zinv := new(fiat.P384Element).Invert(p.z)
    x := new(fiat.P384Element).Mul(p.x, zinv)
    y := new(fiat.P384Element).Mul(p.y, zinv)
    // Encode the sign of the y coordinate (indicated by the least significant
    // bit) as the encoding type (2 or 3).
    buf := append(out[:0], 2)
    buf[0] |= y.Bytes()[p384ElementLength-1] & 1
    buf = append(buf, x.Bytes()...)
    return buf
}

// Add sets q = p1 + p2, and returns q. The points may overlap.
func (q *P384Point) Add(p1, p2 *P384Point) *P384Point {
    // Complete addition formula for a = -3 from "Complete addition formulas for
    // prime order elliptic curves" (https://eprint.iacr.org/2015/1060), §A.2.
    t0 := new(fiat.P384Element).Mul(p1.x, p2.x)  // t0 := X1 * X2
    t1 := new(fiat.P384Element).Mul(p1.y, p2.y)  // t1 := Y1 * Y2
    t2 := new(fiat.P384Element).Mul(p1.z, p2.z)  // t2 := Z1 * Z2
    t3 := new(fiat.P384Element).Add(p1.x, p1.y)  // t3 := X1 + Y1
    t4 := new(fiat.P384Element).Add(p2.x, p2.y)  // t4 := X2 + Y2
    t3.Mul(t3, t4)                               // t3 := t3 * t4
    t4.Add(t0, t1)                               // t4 := t0 + t1
    t3.Sub(t3, t4)                               // t3 := t3 - t4
    t4.Add(p1.y, p1.z)                           // t4 := Y1 + Z1
    x3 := new(fiat.P384Element).Add(p2.y, p2.z)  // X3 := Y2 + Z2
    t4.Mul(t4, x3)                               // t4 := t4 * X3
    x3.Add(t1, t2)                               // X3 := t1 + t2
    t4.Sub(t4, x3)                               // t4 := t4 - X3
    x3.Add(p1.x, p1.z)                           // X3 := X1 + Z1
    y3 := new(fiat.P384Element).Add(p2.x, p2.z)  // Y3 := X2 + Z2
    x3.Mul(x3, y3)                               // X3 := X3 * Y3
    y3.Add(t0, t2)                               // Y3 := t0 + t2
    y3.Sub(x3, y3)                               // Y3 := X3 - Y3
    z3 := new(fiat.P384Element).Mul(p384B(), t2) // Z3 := b * t2
    x3.Sub(y3, z3)                               // X3 := Y3 - Z3
    z3.Add(x3, x3)                               // Z3 := X3 + X3
    x3.Add(x3, z3)                               // X3 := X3 + Z3
    z3.Sub(t1, x3)                               // Z3 := t1 - X3
    x3.Add(t1, x3)                               // X3 := t1 + X3
    y3.Mul(p384B(), y3)                          // Y3 := b * Y3
    t1.Add(t2, t2)                               // t1 := t2 + t2
    t2.Add(t1, t2)                               // t2 := t1 + t2
    y3.Sub(y3, t2)                               // Y3 := Y3 - t2
    y3.Sub(y3, t0)                               // Y3 := Y3 - t0
    t1.Add(y3, y3)                               // t1 := Y3 + Y3
    y3.Add(t1, y3)                               // Y3 := t1 + Y3
    t1.Add(t0, t0)                               // t1 := t0 + t0
    t0.Add(t1, t0)                               // t0 := t1 + t0
    t0.Sub(t0, t2)                               // t0 := t0 - t2
    t1.Mul(t4, y3)                               // t1 := t4 * Y3
    t2.Mul(t0, y3)                               // t2 := t0 * Y3
    y3.Mul(x3, z3)                               // Y3 := X3 * Z3
    y3.Add(y3, t2)                               // Y3 := Y3 + t2
    x3.Mul(t3, x3)                               // X3 := t3 * X3
    x3.Sub(x3, t1)                               // X3 := X3 - t1
    z3.Mul(t4, z3)                               // Z3 := t4 * Z3
    t1.Mul(t3, t0)                               // t1 := t3 * t0
    z3.Add(z3, t1)                               // Z3 := Z3 + t1

    q.x.Set(x3)
    q.y.Set(y3)
    q.z.Set(z3)
    return q
}

// Double sets q = p + p, and returns q. The points may overlap.
func (q *P384Point) Double(p *P384Point) *P384Point {
    // Complete addition formula for a = -3 from "Complete addition formulas for
    // prime order elliptic curves" (https://eprint.iacr.org/2015/1060), §A.2.
    t0 := new(fiat.P384Element).Square(p.x)      // t0 := X ^ 2
    t1 := new(fiat.P384Element).Square(p.y)      // t1 := Y ^ 2
    t2 := new(fiat.P384Element).Square(p.z)      // t2 := Z ^ 2
    t3 := new(fiat.P384Element).Mul(p.x, p.y)    // t3 := X * Y
    t3.Add(t3, t3)                               // t3 := t3 + t3
    z3 := new(fiat.P384Element).Mul(p.x, p.z)    // Z3 := X * Z
    z3.Add(z3, z3)                               // Z3 := Z3 + Z3
    y3 := new(fiat.P384Element).Mul(p384B(), t2) // Y3 := b * t2
    y3.Sub(y3, z3)                               // Y3 := Y3 - Z3
    x3 := new(fiat.P384Element).Add(y3, y3)      // X3 := Y3 + Y3
    y3.Add(x3, y3)                               // Y3 := X3 + Y3
    x3.Sub(t1, y3)                               // X3 := t1 - Y3
    y3.Add(t1, y3)                               // Y3 := t1 + Y3
    y3.Mul(x3, y3)                               // Y3 := X3 * Y3
    x3.Mul(x3, t3)                               // X3 := X3 * t3
    t3.Add(t2, t2)                               // t3 := t2 + t2
    t2.Add(t2, t3)                               // t2 := t2 + t3
    z3.Mul(p384B(), z3)                          // Z3 := b * Z3
    z3.Sub(z3, t2)                               // Z3 := Z3 - t2
    z3.Sub(z3, t0)                               // Z3 := Z3 - t0
    t3.Add(z3, z3)                               // t3 := Z3 + Z3
    z3.Add(z3, t3)                               // Z3 := Z3 + t3
    t3.Add(t0, t0)                               // t3 := t0 + t0
    t0.Add(t3, t0)                               // t0 := t3 + t0
    t0.Sub(t0, t2)                               // t0 := t0 - t2
    t0.Mul(t0, z3)                               // t0 := t0 * Z3
    y3.Add(y3, t0)                               // Y3 := Y3 + t0
    t0.Mul(p.y, p.z)                             // t0 := Y * Z
    t0.Add(t0, t0)                               // t0 := t0 + t0
    z3.Mul(t0, z3)                               // Z3 := t0 * Z3
    x3.Sub(x3, z3)                               // X3 := X3 - Z3
    z3.Mul(t0, t1)                               // Z3 := t0 * t1
    z3.Add(z3, z3)                               // Z3 := Z3 + Z3
    z3.Add(z3, z3)                               // Z3 := Z3 + Z3

    q.x.Set(x3)
    q.y.Set(y3)
    q.z.Set(z3)
    return q
}

// Select sets q to p1 if cond == 1, and to p2 if cond == 0.
func (q *P384Point) Select(p1, p2 *P384Point, cond int) *P384Point {
    q.x.Select(p1.x, p2.x, cond)
    q.y.Select(p1.y, p2.y, cond)
    q.z.Select(p1.z, p2.z, cond)
    return q
}

// A p384Table holds the first 15 multiples of a point at offset -1, so [1]P
// is at table[0], [15]P is at table[14], and [0]P is implicitly the identity
// point.
type p384Table [15]*P384Point

// Select selects the n-th multiple of the table base point into p. It works in
// constant time by iterating over every entry of the table. n must be in [0, 15].
func (table *p384Table) Select(p *P384Point, n uint8) {
    if n >= 16 {
        panic("bign: internal error: p384Table called with out-of-bounds value")
    }
    p.Set(NewP384Point())
    for i := uint8(1); i < 16; i++ {
        cond := subtle.ConstantTimeByteEq(i, n)
        p.Select(table[i-1], p, cond)
    }
}

// ScalarMult sets p = scalar * q, and returns p.
func (p *P384Point) ScalarMult(q *P384Point, scalar []byte) (*P384Point, error) {
    // Compute a p384Table for the base point q. The explicit NewP384Point
    // calls get inlined, letting the allocations live on the stack.
    var table = p384Table{NewP384Point(), NewP384Point(), NewP384Point(),
        NewP384Point(), NewP384Point(), NewP384Point(), NewP384Point(),
        NewP384Point(), NewP384Point(), NewP384Point(), NewP384Point(),
        NewP384Point(), NewP384Point(), NewP384Point(), NewP384Point()}
    table[0].Set(q)
    for i := 1; i < 15; i += 2 {
        table[i].Double(table[i/2])
        table[i+1].Add(table[i], q)
    }
    // Instead of doing the classic double-and-add chain, we do it with a
    // four-bit window: we double four times, and then add [0-15]P.
    t := NewP384Point()
    p.Set(NewP384Point())
    for i, byte := range scalar {
        // No need to double on the first iteration, as p is the identity at
        // this point, and [N]∞ = ∞.
        if i != 0 {
            p.Double(p)
            p.Double(p)
            p.Double(p)
            p.Double(p)
        }
        windowValue := byte >> 4
        table.Select(t, windowValue)
        p.Add(p, t)
        p.Double(p)
        p.Double(p)
        p.Double(p)
        p.Double(p)
        windowValue = byte & 0b1111
        table.Select(t, windowValue)
        p.Add(p, t)
    }
    return p, nil
}

var p384GeneratorTable *[p384ElementLength * 2]p384Table
var p384GeneratorTableOnce sync.Once

// generatorTable returns a sequence of p384Tables. The first table contains
// multiples of G. Each successive table is the previous table doubled four
// times.
func (p *P384Point) generatorTable() *[p384ElementLength * 2]p384Table {
    p384GeneratorTableOnce.Do(func() {
        p384GeneratorTable = new([p384ElementLength * 2]p384Table)
        base := NewP384Point().SetGenerator()
        for i := 0; i < p384ElementLength*2; i++ {
            p384GeneratorTable[i][0] = NewP384Point().Set(base)
            for j := 1; j < 15; j++ {
                p384GeneratorTable[i][j] = NewP384Point().Add(p384GeneratorTable[i][j-1], base)
            }
            base.Double(base)
            base.Double(base)
            base.Double(base)
            base.Double(base)
        }
    })
    return p384GeneratorTable
}

// ScalarBaseMult sets p = scalar * B, where B is the canonical generator, and
// returns p.
func (p *P384Point) ScalarBaseMult(scalar []byte) (*P384Point, error) {
    if len(scalar) != p384ElementLength {
        return nil, errors.New("invalid scalar length")
    }
    tables := p.generatorTable()
    // This is also a scalar multiplication with a four-bit window like in
    // ScalarMult, but in this case the doublings are precomputed. The value
    // [windowValue]G added at iteration k would normally get doubled
    // (totIterations-k)×4 times, but with a larger precomputation we can
    // instead add [2^((totIterations-k)×4)][windowValue]G and avoid the
    // doublings between iterations.
    t := NewP384Point()
    p.Set(NewP384Point())
    tableIndex := len(tables) - 1
    for _, byte := range scalar {
        windowValue := byte >> 4
        tables[tableIndex].Select(t, windowValue)
        p.Add(p, t)
        tableIndex--

        windowValue = byte & 0b1111
        tables[tableIndex].Select(t, windowValue)
        p.Add(p, t)
        tableIndex--
    }

    return p, nil
}

// p384Sqrt sets e to a square root of x. If x is not a square, p384Sqrt returns
// false and e is unchanged. e and x can overlap.
func p384Sqrt(e, x *fiat.P384Element) (isSquare bool) {
    candidate := new(fiat.P384Element)
    p384SqrtCandidate(candidate, x)
    square := new(fiat.P384Element).Square(candidate)
    if square.Equal(x) != 1 {
        return false
    }
    e.Set(candidate)
    return true
}

// p384SqrtCandidate sets z to a square root candidate for x. z and x must not overlap.
func p384SqrtCandidate(z, x *fiat.P384Element) {
    // Since p = 3 mod 4, exponentiation by (p + 1) / 4 yields a square root candidate.
    //
    // The sequence of 14 multiplications and 381 squarings is derived from the
    // following addition chain generated with github.com/mmcloughlin/addchain v0.4.0.
    //
    //	_10       = 2*1
    //	_11       = 1 + _10
    //	_1100     = _11 << 2
    //	_1111     = _11 + _1100
    //	_11110000 = _1111 << 4
    //	_11111111 = _1111 + _11110000
    //	x16       = _11111111 << 8 + _11111111
    //	x20       = x16 << 4 + _1111
    //	x22       = x20 << 2 + _11
    //	x44       = x22 << 22 + x22
    //	x88       = x44 << 44 + x44
    //	x176      = x88 << 88 + x88
    //	x352      = x176 << 176 + x176
    //	x374      = x352 << 22 + x22
    //	x375      = 2*x374 + 1
    //	return      (x375 << 3 + _11) << 4 + 1
    //
    var t0 = new(fiat.P384Element)
    var t1 = new(fiat.P384Element)
    var t2 = new(fiat.P384Element)

    z.Square(x)
    z.Mul(x, z)
    t0.Square(z)
    for s := 1; s < 2; s++ {
        t0.Square(t0)
    }
    t0.Mul(z, t0)
    t1.Square(t0)
    for s := 1; s < 4; s++ {
        t1.Square(t1)
    }
    t1.Mul(t0, t1)
    t2.Square(t1)
    for s := 1; s < 8; s++ {
        t2.Square(t2)
    }
    t1.Mul(t1, t2)
    for s := 0; s < 4; s++ {
        t1.Square(t1)
    }
    t0.Mul(t0, t1)
    for s := 0; s < 2; s++ {
        t0.Square(t0)
    }
    t0.Mul(z, t0)
    t1.Square(t0)
    for s := 1; s < 22; s++ {
        t1.Square(t1)
    }
    t1.Mul(t0, t1)
    t2.Square(t1)
    for s := 1; s < 44; s++ {
        t2.Square(t2)
    }
    t1.Mul(t1, t2)
    t2.Square(t1)
    for s := 1; s < 88; s++ {
        t2.Square(t2)
    }
    t1.Mul(t1, t2)
    t2.Square(t1)
    for s := 1; s < 176; s++ {
        t2.Square(t2)
    }
    t1.Mul(t1, t2)
    for s := 0; s < 22; s++ {
        t1.Square(t1)
    }
    t0.Mul(t0, t1)
    t0.Square(t0)
    t0.Mul(x, t0)
    for s := 0; s < 3; s++ {
        t0.Square(t0)
    }
    z.Mul(z, t0)
    for s := 0; s < 4; s++ {
        z.Square(z)
    }
    z.Mul(x, z)
}
