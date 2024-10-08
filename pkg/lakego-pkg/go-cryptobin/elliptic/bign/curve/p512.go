package bign

import (
    "crypto/subtle"
    "errors"
    "sync"

    "github.com/deatil/go-cryptobin/elliptic/bign/curve/fiat"
)

// p512ElementLength is the length of an element of the base or scalar field,
// which have the same bytes length for all NIST P curves.
const p512ElementLength = 64

// P512Point is a P512 point. The zero value is NOT valid.
type P512Point struct {
    // The point is represented in projective coordinates (X:Y:Z),
    // where x = X/Z and y = Y/Z.
    x, y, z *fiat.P512Element
}

// NewP512Point returns a new P512Point representing the point at infinity point.
func NewP512Point() *P512Point {
    return &P512Point{
        x: new(fiat.P512Element),
        y: new(fiat.P512Element).One(),
        z: new(fiat.P512Element),
    }
}

// SetGenerator sets p to the canonical generator and returns p.
func (p *P512Point) SetGenerator() *P512Point {
    p.x.SetBytes([]byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0})
    p.y.SetBytes([]byte{0xa8, 0x26, 0xff, 0x7a, 0xe4, 0x3, 0x76, 0x81, 0xb1, 0x82, 0xe6, 0xf7, 0xa0, 0xd1, 0x8f, 0xab, 0xb0, 0xab, 0x41, 0xb3, 0xb3, 0x61, 0xbc, 0xe2, 0xd2, 0xed, 0xf8, 0x1b, 0x0, 0xcc, 0xca, 0xda, 0x69, 0x73, 0xdd, 0xe2, 0xe, 0xfa, 0x6f, 0xd2, 0xff, 0x77, 0x73, 0x95, 0xee, 0xe8, 0x22, 0x61, 0x67, 0xaa, 0x83, 0xb9, 0xc9, 0x4c, 0xd, 0x4, 0xb7, 0x92, 0xae, 0x6f, 0xce, 0xef, 0xed, 0xbd})
    p.z.One()
    return p
}

// Set sets p = q and returns p.
func (p *P512Point) Set(q *P512Point) *P512Point {
    p.x.Set(q.x)
    p.y.Set(q.y)
    p.z.Set(q.z)
    return p
}

// SetBytes sets p to the compressed, uncompressed, or infinity value encoded in
// b, as specified in SEC 1, Version 2.0, Section 2.3.4. If the point is not on
// the curve, it returns nil and an error, and the receiver is unchanged.
// Otherwise, it returns p.
func (p *P512Point) SetBytes(b []byte) (*P512Point, error) {
    switch {
    // Point at infinity.
    case len(b) == 1 && b[0] == 0:
        return p.Set(NewP512Point()), nil
    // Uncompressed form.
    case len(b) == 1+2*p512ElementLength && b[0] == 4:
        x, err := new(fiat.P512Element).SetBytes(b[1 : 1+p512ElementLength])
        if err != nil {
            return nil, err
        }
        y, err := new(fiat.P512Element).SetBytes(b[1+p512ElementLength:])
        if err != nil {
            return nil, err
        }
        if err := p512CheckOnCurve(x, y); err != nil {
            return nil, err
        }
        p.x.Set(x)
        p.y.Set(y)
        p.z.One()
        return p, nil
    // Compressed form.
    case len(b) == 1+p512ElementLength && (b[0] == 2 || b[0] == 3):
        x, err := new(fiat.P512Element).SetBytes(b[1:])
        if err != nil {
            return nil, err
        }
        // y² = x³ - 3x + b
        y := p512Polynomial(new(fiat.P512Element), x)
        if !p512Sqrt(y, y) {
            return nil, errors.New("invalid P512 compressed point encoding")
        }
        // Select the positive or negative root, as indicated by the least
        // significant bit, based on the encoding type byte.
        otherRoot := new(fiat.P512Element)
        otherRoot.Sub(otherRoot, y)
        cond := y.Bytes()[p512ElementLength-1]&1 ^ b[0]&1
        y.Select(otherRoot, y, int(cond))
        p.x.Set(x)
        p.y.Set(y)
        p.z.One()
        return p, nil
    default:
        return nil, errors.New("invalid P512 point encoding")
    }
}

var _p512B *fiat.P512Element
var _p512BOnce sync.Once

func p512B() *fiat.P512Element {
    _p512BOnce.Do(func() {
        _p512B, _ = new(fiat.P512Element).SetBytes([]byte{0x6c, 0xb4, 0x59, 0x44, 0x93, 0x3b, 0x8c, 0x43, 0xd8, 0x8c, 0x5d, 0x6a, 0x60, 0xfd, 0x58, 0x89, 0x5b, 0xc6, 0xa9, 0xee, 0xdd, 0x5d, 0x25, 0x51, 0x17, 0xce, 0x13, 0xe3, 0xda, 0xad, 0xb0, 0x88, 0x27, 0x11, 0xdc, 0xb5, 0xc4, 0x24, 0x5e, 0x95, 0x29, 0x33, 0x0, 0x8c, 0x87, 0xac, 0xa2, 0x43, 0xea, 0x86, 0x22, 0x27, 0x3a, 0x49, 0xa2, 0x7a, 0x9, 0x34, 0x69, 0x98, 0xd6, 0x13, 0x9c, 0x90})
    })
    return _p512B
}

// p512Polynomial sets y2 to x³ - 3x + b, and returns y2.
func p512Polynomial(y2, x *fiat.P512Element) *fiat.P512Element {
    y2.Square(x)
    y2.Mul(y2, x)

    threeX := new(fiat.P512Element).Add(x, x)
    threeX.Add(threeX, x)

    y2.Sub(y2, threeX)

    return y2.Add(y2, p512B())
}

func p512CheckOnCurve(x, y *fiat.P512Element) error {
    // y² = x³ - 3x + b
    rhs := p512Polynomial(new(fiat.P512Element), x)
    lhs := new(fiat.P512Element).Square(y)
    if rhs.Equal(lhs) != 1 {
        return errors.New("P512 point not on curve")
    }
    return nil
}

// Bytes returns the uncompressed or infinity encoding of p, as specified in
// SEC 1, Version 2.0, Section 2.3.3. Note that the encoding of the point at
// infinity is shorter than all other encodings.
func (p *P512Point) Bytes() []byte {
    // This function is outlined to make the allocations inline in the caller
    // rather than happen on the heap.
    var out [1 + 2*p512ElementLength]byte
    return p.bytes(&out)
}

func (p *P512Point) bytes(out *[1 + 2*p512ElementLength]byte) []byte {
    if p.z.IsZero() == 1 {
        return append(out[:0], 0)
    }
    zinv := new(fiat.P512Element).Invert(p.z)
    x := new(fiat.P512Element).Mul(p.x, zinv)
    y := new(fiat.P512Element).Mul(p.y, zinv)
    buf := append(out[:0], 4)
    buf = append(buf, x.Bytes()...)
    buf = append(buf, y.Bytes()...)
    return buf
}

// BytesX returns the encoding of the x-coordinate of p, as specified in SEC 1,
// Version 2.0, Section 2.3.5, or an error if p is the point at infinity.
func (p *P512Point) BytesX() ([]byte, error) {
    // This function is outlined to make the allocations inline in the caller
    // rather than happen on the heap.
    var out [p512ElementLength]byte
    return p.bytesX(&out)
}

func (p *P512Point) bytesX(out *[p512ElementLength]byte) ([]byte, error) {
    if p.z.IsZero() == 1 {
        return nil, errors.New("P512 point is the point at infinity")
    }
    zinv := new(fiat.P512Element).Invert(p.z)
    x := new(fiat.P512Element).Mul(p.x, zinv)
    return append(out[:0], x.Bytes()...), nil
}

// BytesCompressed returns the compressed or infinity encoding of p, as
// specified in SEC 1, Version 2.0, Section 2.3.3. Note that the encoding of the
// point at infinity is shorter than all other encodings.
func (p *P512Point) BytesCompressed() []byte {
    // This function is outlined to make the allocations inline in the caller
    // rather than happen on the heap.
    var out [1 + p512ElementLength]byte
    return p.bytesCompressed(&out)
}

func (p *P512Point) bytesCompressed(out *[1 + p512ElementLength]byte) []byte {
    if p.z.IsZero() == 1 {
        return append(out[:0], 0)
    }
    zinv := new(fiat.P512Element).Invert(p.z)
    x := new(fiat.P512Element).Mul(p.x, zinv)
    y := new(fiat.P512Element).Mul(p.y, zinv)
    // Encode the sign of the y coordinate (indicated by the least significant
    // bit) as the encoding type (2 or 3).
    buf := append(out[:0], 2)
    buf[0] |= y.Bytes()[p512ElementLength-1] & 1
    buf = append(buf, x.Bytes()...)
    return buf
}

// Add sets q = p1 + p2, and returns q. The points may overlap.
func (q *P512Point) Add(p1, p2 *P512Point) *P512Point {
    // Complete addition formula for a = -3 from "Complete addition formulas for
    // prime order elliptic curves" (https://eprint.iacr.org/2015/1060), §A.2.
    t0 := new(fiat.P512Element).Mul(p1.x, p2.x)  // t0 := X1 * X2
    t1 := new(fiat.P512Element).Mul(p1.y, p2.y)  // t1 := Y1 * Y2
    t2 := new(fiat.P512Element).Mul(p1.z, p2.z)  // t2 := Z1 * Z2
    t3 := new(fiat.P512Element).Add(p1.x, p1.y)  // t3 := X1 + Y1
    t4 := new(fiat.P512Element).Add(p2.x, p2.y)  // t4 := X2 + Y2
    t3.Mul(t3, t4)                               // t3 := t3 * t4
    t4.Add(t0, t1)                               // t4 := t0 + t1
    t3.Sub(t3, t4)                               // t3 := t3 - t4
    t4.Add(p1.y, p1.z)                           // t4 := Y1 + Z1
    x3 := new(fiat.P512Element).Add(p2.y, p2.z)  // X3 := Y2 + Z2
    t4.Mul(t4, x3)                               // t4 := t4 * X3
    x3.Add(t1, t2)                               // X3 := t1 + t2
    t4.Sub(t4, x3)                               // t4 := t4 - X3
    x3.Add(p1.x, p1.z)                           // X3 := X1 + Z1
    y3 := new(fiat.P512Element).Add(p2.x, p2.z)  // Y3 := X2 + Z2
    x3.Mul(x3, y3)                               // X3 := X3 * Y3
    y3.Add(t0, t2)                               // Y3 := t0 + t2
    y3.Sub(x3, y3)                               // Y3 := X3 - Y3
    z3 := new(fiat.P512Element).Mul(p512B(), t2) // Z3 := b * t2
    x3.Sub(y3, z3)                               // X3 := Y3 - Z3
    z3.Add(x3, x3)                               // Z3 := X3 + X3
    x3.Add(x3, z3)                               // X3 := X3 + Z3
    z3.Sub(t1, x3)                               // Z3 := t1 - X3
    x3.Add(t1, x3)                               // X3 := t1 + X3
    y3.Mul(p512B(), y3)                          // Y3 := b * Y3
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
func (q *P512Point) Double(p *P512Point) *P512Point {
    // Complete addition formula for a = -3 from "Complete addition formulas for
    // prime order elliptic curves" (https://eprint.iacr.org/2015/1060), §A.2.
    t0 := new(fiat.P512Element).Square(p.x)      // t0 := X ^ 2
    t1 := new(fiat.P512Element).Square(p.y)      // t1 := Y ^ 2
    t2 := new(fiat.P512Element).Square(p.z)      // t2 := Z ^ 2
    t3 := new(fiat.P512Element).Mul(p.x, p.y)    // t3 := X * Y
    t3.Add(t3, t3)                               // t3 := t3 + t3
    z3 := new(fiat.P512Element).Mul(p.x, p.z)    // Z3 := X * Z
    z3.Add(z3, z3)                               // Z3 := Z3 + Z3
    y3 := new(fiat.P512Element).Mul(p512B(), t2) // Y3 := b * t2
    y3.Sub(y3, z3)                               // Y3 := Y3 - Z3
    x3 := new(fiat.P512Element).Add(y3, y3)      // X3 := Y3 + Y3
    y3.Add(x3, y3)                               // Y3 := X3 + Y3
    x3.Sub(t1, y3)                               // X3 := t1 - Y3
    y3.Add(t1, y3)                               // Y3 := t1 + Y3
    y3.Mul(x3, y3)                               // Y3 := X3 * Y3
    x3.Mul(x3, t3)                               // X3 := X3 * t3
    t3.Add(t2, t2)                               // t3 := t2 + t2
    t2.Add(t2, t3)                               // t2 := t2 + t3
    z3.Mul(p512B(), z3)                          // Z3 := b * Z3
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
func (q *P512Point) Select(p1, p2 *P512Point, cond int) *P512Point {
    q.x.Select(p1.x, p2.x, cond)
    q.y.Select(p1.y, p2.y, cond)
    q.z.Select(p1.z, p2.z, cond)
    return q
}

// A p512Table holds the first 15 multiples of a point at offset -1, so [1]P
// is at table[0], [15]P is at table[14], and [0]P is implicitly the identity
// point.
type p512Table [15]*P512Point

// Select selects the n-th multiple of the table base point into p. It works in
// constant time by iterating over every entry of the table. n must be in [0, 15].
func (table *p512Table) Select(p *P512Point, n uint8) {
    if n >= 16 {
        panic("bign: internal error: p512Table called with out-of-bounds value")
    }
    p.Set(NewP512Point())
    for i := uint8(1); i < 16; i++ {
        cond := subtle.ConstantTimeByteEq(i, n)
        p.Select(table[i-1], p, cond)
    }
}

// ScalarMult sets p = scalar * q, and returns p.
func (p *P512Point) ScalarMult(q *P512Point, scalar []byte) (*P512Point, error) {
    // Compute a p512Table for the base point q. The explicit NewP512Point
    // calls get inlined, letting the allocations live on the stack.
    var table = p512Table{NewP512Point(), NewP512Point(), NewP512Point(),
        NewP512Point(), NewP512Point(), NewP512Point(), NewP512Point(),
        NewP512Point(), NewP512Point(), NewP512Point(), NewP512Point(),
        NewP512Point(), NewP512Point(), NewP512Point(), NewP512Point()}
    table[0].Set(q)
    for i := 1; i < 15; i += 2 {
        table[i].Double(table[i/2])
        table[i+1].Add(table[i], q)
    }
    // Instead of doing the classic double-and-add chain, we do it with a
    // four-bit window: we double four times, and then add [0-15]P.
    t := NewP512Point()
    p.Set(NewP512Point())
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

var p512GeneratorTable *[p512ElementLength * 2]p512Table
var p512GeneratorTableOnce sync.Once

// generatorTable returns a sequence of p512Tables. The first table contains
// multiples of G. Each successive table is the previous table doubled four
// times.
func (p *P512Point) generatorTable() *[p512ElementLength * 2]p512Table {
    p512GeneratorTableOnce.Do(func() {
        p512GeneratorTable = new([p512ElementLength * 2]p512Table)
        base := NewP512Point().SetGenerator()
        for i := 0; i < p512ElementLength*2; i++ {
            p512GeneratorTable[i][0] = NewP512Point().Set(base)
            for j := 1; j < 15; j++ {
                p512GeneratorTable[i][j] = NewP512Point().Add(p512GeneratorTable[i][j-1], base)
            }
            base.Double(base)
            base.Double(base)
            base.Double(base)
            base.Double(base)
        }
    })
    return p512GeneratorTable
}

// ScalarBaseMult sets p = scalar * B, where B is the canonical generator, and
// returns p.
func (p *P512Point) ScalarBaseMult(scalar []byte) (*P512Point, error) {
    if len(scalar) != p512ElementLength {
        return nil, errors.New("invalid scalar length")
    }
    tables := p.generatorTable()
    // This is also a scalar multiplication with a four-bit window like in
    // ScalarMult, but in this case the doublings are precomputed. The value
    // [windowValue]G added at iteration k would normally get doubled
    // (totIterations-k)×4 times, but with a larger precomputation we can
    // instead add [2^((totIterations-k)×4)][windowValue]G and avoid the
    // doublings between iterations.
    t := NewP512Point()
    p.Set(NewP512Point())
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

// p512Sqrt sets e to a square root of x. If x is not a square, p512Sqrt returns
// false and e is unchanged. e and x can overlap.
func p512Sqrt(e, x *fiat.P512Element) (isSquare bool) {
    candidate := new(fiat.P512Element)
    p512SqrtCandidate(candidate, x)
    square := new(fiat.P512Element).Square(candidate)
    if square.Equal(x) != 1 {
        return false
    }
    e.Set(candidate)
    return true
}

// p512SqrtCandidate sets z to a square root candidate for x. z and x must not overlap.
func p512SqrtCandidate(z, x *fiat.P512Element) {
    // Since p = 3 mod 4, exponentiation by (p + 1) / 4 yields a square root candidate.
    //
    // The sequence of 15 multiplications and 509 squarings is derived from the
    // following addition chain generated with github.com/mmcloughlin/addchain v0.4.0.
    //
    //	_10     = 2*1
    //	_11     = 1 + _10
    //	_110    = 2*_11
    //	_111    = 1 + _110
    //	_111000 = _111 << 3
    //	_111111 = _111 + _111000
    //	x9      = _111111 << 3 + _111
    //	x18     = x9 << 9 + x9
    //	x21     = x18 << 3 + _111
    //	x30     = x21 << 9 + x9
    //	x60     = x30 << 30 + x30
    //	x120    = x60 << 60 + x60
    //	x240    = x120 << 120 + x120
    //	x480    = x240 << 240 + x240
    //	x501    = x480 << 21 + x21
    //	x502    = 2*x501 + 1
    //	return    2*((x502 << 4 + _111) << 3 + 1)
    //
    var t0 = new(fiat.P512Element)
    var t1 = new(fiat.P512Element)
    var t2 = new(fiat.P512Element)

    z.Square(x)
    z.Mul(x, z)
    z.Square(z)
    z.Mul(x, z)
    t0.Square(z)
    for s := 1; s < 3; s++ {
        t0.Square(t0)
    }
    t0.Mul(z, t0)
    for s := 0; s < 3; s++ {
        t0.Square(t0)
    }
    t1.Mul(z, t0)
    t0.Square(t1)
    for s := 1; s < 9; s++ {
        t0.Square(t0)
    }
    t0.Mul(t1, t0)
    for s := 0; s < 3; s++ {
        t0.Square(t0)
    }
    t0.Mul(z, t0)
    t2.Square(t0)
    for s := 1; s < 9; s++ {
        t2.Square(t2)
    }
    t1.Mul(t1, t2)
    t2.Square(t1)
    for s := 1; s < 30; s++ {
        t2.Square(t2)
    }
    t1.Mul(t1, t2)
    t2.Square(t1)
    for s := 1; s < 60; s++ {
        t2.Square(t2)
    }
    t1.Mul(t1, t2)
    t2.Square(t1)
    for s := 1; s < 120; s++ {
        t2.Square(t2)
    }
    t1.Mul(t1, t2)
    t2.Square(t1)
    for s := 1; s < 240; s++ {
        t2.Square(t2)
    }
    t1.Mul(t1, t2)
    for s := 0; s < 21; s++ {
        t1.Square(t1)
    }
    t0.Mul(t0, t1)
    t0.Square(t0)
    t0.Mul(x, t0)
    for s := 0; s < 4; s++ {
        t0.Square(t0)
    }
    z.Mul(z, t0)
    for s := 0; s < 3; s++ {
        z.Square(z)
    }
    z.Mul(x, z)
    z.Square(z)
}
