//go:build !amd64 && !arm64 || purego
// +build !amd64,!arm64 purego

package curve

import (
    "sync"
    "errors"
    "crypto/subtle"

    "github.com/deatil/go-cryptobin/gm/sm2/curve/field"
)

// p256ElementLength is the length of an element of the base or scalar field,
// which have the same bytes length for all NIST P curves.
const p256ElementLength = 32

// Point is a SM2P256 point. The zero value is NOT valid.
type Point struct {
    // The point is represented in projective coordinates (X:Y:Z),
    // where x = X/Z and y = Y/Z.
    x, y, z *field.Element
}

// NewPoint returns a new Point representing the point at infinity point.
func NewPoint() *Point {
    return &Point{
        x: new(field.Element),
        y: new(field.Element).One(),
        z: new(field.Element),
    }
}

// SetGenerator sets p to the canonical generator and returns p.
func (p *Point) SetGenerator() *Point {
    p.x.SetBytes([]byte{0x32, 0xc4, 0xae, 0x2c, 0x1f, 0x19, 0x81, 0x19, 0x5f, 0x99, 0x4, 0x46, 0x6a, 0x39, 0xc9, 0x94, 0x8f, 0xe3, 0xb, 0xbf, 0xf2, 0x66, 0xb, 0xe1, 0x71, 0x5a, 0x45, 0x89, 0x33, 0x4c, 0x74, 0xc7})
    p.y.SetBytes([]byte{0xbc, 0x37, 0x36, 0xa2, 0xf4, 0xf6, 0x77, 0x9c, 0x59, 0xbd, 0xce, 0xe3, 0x6b, 0x69, 0x21, 0x53, 0xd0, 0xa9, 0x87, 0x7c, 0xc6, 0x2a, 0x47, 0x40, 0x2, 0xdf, 0x32, 0xe5, 0x21, 0x39, 0xf0, 0xa0})
    p.z.One()
    return p
}

// Set sets p = q and returns p.
func (p *Point) Set(q *Point) *Point {
    p.x.Set(q.x)
    p.y.Set(q.y)
    p.z.Set(q.z)
    return p
}

// SetBytes sets p to the compressed, uncompressed, or infinity value encoded in
// b, as specified in SEC 1, Version 2.0, Section 2.3.4. If the point is not on
// the curve, it returns nil and an error, and the receiver is unchanged.
// Otherwise, it returns p.
func (p *Point) SetBytes(b []byte) (*Point, error) {
    switch {
        // Point at infinity.
        case len(b) == 1 && b[0] == 0:
            return p.Set(NewPoint()), nil
        // Uncompressed form.
        case len(b) == 1+2*p256ElementLength && b[0] == 4:
            x, err := new(field.Element).SetBytes(b[1 : 1+p256ElementLength])
            if err != nil {
                return nil, err
            }
            y, err := new(field.Element).SetBytes(b[1+p256ElementLength:])
            if err != nil {
                return nil, err
            }
            if err := p256CheckOnCurve(x, y); err != nil {
                return nil, err
            }
            p.x.Set(x)
            p.y.Set(y)
            p.z.One()
            return p, nil
        // Compressed form.
        case len(b) == 1+p256ElementLength && (b[0] == 2 || b[0] == 3):
            x, err := new(field.Element).SetBytes(b[1:])
            if err != nil {
                return nil, err
            }
            // y² = x³ - 3x + b
            y := p256Polynomial(new(field.Element), x)
            if !p256Sqrt(y, y) {
                return nil, errors.New("cryptobin/sm2: invalid compressed point encoding")
            }
            // Select the positive or negative root, as indicated by the least
            // significant bit, based on the encoding type byte.
            otherRoot := new(field.Element)
            otherRoot.Sub(otherRoot, y)
            cond := y.Bytes()[p256ElementLength-1]&1 ^ b[0]&1
            y.Select(otherRoot, y, int(cond))
            p.x.Set(x)
            p.y.Set(y)
            p.z.One()
            return p, nil
        default:
            return nil, errors.New("cryptobin/sm2: invalid point encoding")
    }
}

var _p256B *field.Element
var _p256BOnce sync.Once

func p256B() *field.Element {
    _p256BOnce.Do(func() {
        _p256B, _ = new(field.Element).SetBytes([]byte{0x28, 0xe9, 0xfa, 0x9e, 0x9d, 0x9f, 0x5e, 0x34, 0x4d, 0x5a, 0x9e, 0x4b, 0xcf, 0x65, 0x9, 0xa7, 0xf3, 0x97, 0x89, 0xf5, 0x15, 0xab, 0x8f, 0x92, 0xdd, 0xbc, 0xbd, 0x41, 0x4d, 0x94, 0xe, 0x93})
    })
    return _p256B
}

// p256Polynomial sets y2 to x³ - 3x + b, and returns y2.
func p256Polynomial(y2, x *field.Element) *field.Element {
    y2.Square(x)
    y2.Mul(y2, x)

    threeX := new(field.Element).Add(x, x)
    threeX.Add(threeX, x)

    y2.Sub(y2, threeX)

    return y2.Add(y2, p256B())
}

func p256CheckOnCurve(x, y *field.Element) error {
    // y² = x³ - 3x + b
    rhs := p256Polynomial(new(field.Element), x)
    lhs := new(field.Element).Square(y)
    if rhs.Equal(lhs) != 1 {
        return errors.New("cryptobin/sm2: point not on curve")
    }
    return nil
}

// Bytes returns the uncompressed or infinity encoding of p, as specified in
// SEC 1, Version 2.0, Section 2.3.3. Note that the encoding of the point at
// infinity is shorter than all other encodings.
func (p *Point) Bytes() []byte {
    // This function is outlined to make the allocations inline in the caller
    // rather than happen on the heap.
    var out [1 + 2*p256ElementLength]byte
    return p.bytes(&out)
}

func (p *Point) bytes(out *[1 + 2*p256ElementLength]byte) []byte {
    if p.z.IsZero() == 1 {
        return append(out[:0], 0)
    }
    zinv := new(field.Element).Invert(p.z)
    x := new(field.Element).Mul(p.x, zinv)
    y := new(field.Element).Mul(p.y, zinv)
    buf := append(out[:0], 4)
    buf = append(buf, x.Bytes()...)
    buf = append(buf, y.Bytes()...)
    return buf
}

// BytesX returns the encoding of the x-coordinate of p, as specified in SEC 1,
// Version 2.0, Section 2.3.5, or an error if p is the point at infinity.
func (p *Point) BytesX() ([]byte, error) {
    // This function is outlined to make the allocations inline in the caller
    // rather than happen on the heap.
    var out [p256ElementLength]byte
    return p.bytesX(&out)
}

func (p *Point) bytesX(out *[p256ElementLength]byte) ([]byte, error) {
    if p.z.IsZero() == 1 {
        return nil, errors.New("cryptobin/sm2: point is the point at infinity")
    }
    zinv := new(field.Element).Invert(p.z)
    x := new(field.Element).Mul(p.x, zinv)
    return append(out[:0], x.Bytes()...), nil
}

// BytesCompressed returns the compressed or infinity encoding of p, as
// specified in SEC 1, Version 2.0, Section 2.3.3. Note that the encoding of the
// point at infinity is shorter than all other encodings.
func (p *Point) BytesCompressed() []byte {
    // This function is outlined to make the allocations inline in the caller
    // rather than happen on the heap.
    var out [1 + p256ElementLength]byte
    return p.bytesCompressed(&out)
}

func (p *Point) bytesCompressed(out *[1 + p256ElementLength]byte) []byte {
    if p.z.IsZero() == 1 {
        return append(out[:0], 0)
    }
    zinv := new(field.Element).Invert(p.z)
    x := new(field.Element).Mul(p.x, zinv)
    y := new(field.Element).Mul(p.y, zinv)
    // Encode the sign of the y coordinate (indicated by the least significant
    // bit) as the encoding type (2 or 3).
    buf := append(out[:0], 2)
    buf[0] |= y.Bytes()[p256ElementLength-1] & 1
    buf = append(buf, x.Bytes()...)
    return buf
}

// Add sets q = p1 + p2, and returns q. The points may overlap.
func (q *Point) Add(p1, p2 *Point) *Point {
    // Complete addition formula for a = -3 from "Complete addition formulas for
    // prime order elliptic curves" (https://eprint.iacr.org/2015/1060), §A.2.
    t0 := new(field.Element).Mul(p1.x, p2.x)  // t0 := X1 * X2
    t1 := new(field.Element).Mul(p1.y, p2.y)  // t1 := Y1 * Y2
    t2 := new(field.Element).Mul(p1.z, p2.z)  // t2 := Z1 * Z2
    t3 := new(field.Element).Add(p1.x, p1.y)  // t3 := X1 + Y1
    t4 := new(field.Element).Add(p2.x, p2.y)  // t4 := X2 + Y2
    t3.Mul(t3, t4)                            // t3 := t3 * t4
    t4.Add(t0, t1)                            // t4 := t0 + t1
    t3.Sub(t3, t4)                            // t3 := t3 - t4
    t4.Add(p1.y, p1.z)                        // t4 := Y1 + Z1
    x3 := new(field.Element).Add(p2.y, p2.z)  // X3 := Y2 + Z2
    t4.Mul(t4, x3)                            // t4 := t4 * X3
    x3.Add(t1, t2)                            // X3 := t1 + t2
    t4.Sub(t4, x3)                            // t4 := t4 - X3
    x3.Add(p1.x, p1.z)                        // X3 := X1 + Z1
    y3 := new(field.Element).Add(p2.x, p2.z)  // Y3 := X2 + Z2
    x3.Mul(x3, y3)                            // X3 := X3 * Y3
    y3.Add(t0, t2)                            // Y3 := t0 + t2
    y3.Sub(x3, y3)                            // Y3 := X3 - Y3
    z3 := new(field.Element).Mul(p256B(), t2) // Z3 := b * t2
    x3.Sub(y3, z3)                            // X3 := Y3 - Z3
    z3.Add(x3, x3)                            // Z3 := X3 + X3
    x3.Add(x3, z3)                            // X3 := X3 + Z3
    z3.Sub(t1, x3)                            // Z3 := t1 - X3
    x3.Add(t1, x3)                            // X3 := t1 + X3
    y3.Mul(p256B(), y3)                       // Y3 := b * Y3
    t1.Add(t2, t2)                            // t1 := t2 + t2
    t2.Add(t1, t2)                            // t2 := t1 + t2
    y3.Sub(y3, t2)                            // Y3 := Y3 - t2
    y3.Sub(y3, t0)                            // Y3 := Y3 - t0
    t1.Add(y3, y3)                            // t1 := Y3 + Y3
    y3.Add(t1, y3)                            // Y3 := t1 + Y3
    t1.Add(t0, t0)                            // t1 := t0 + t0
    t0.Add(t1, t0)                            // t0 := t1 + t0
    t0.Sub(t0, t2)                            // t0 := t0 - t2
    t1.Mul(t4, y3)                            // t1 := t4 * Y3
    t2.Mul(t0, y3)                            // t2 := t0 * Y3
    y3.Mul(x3, z3)                            // Y3 := X3 * Z3
    y3.Add(y3, t2)                            // Y3 := Y3 + t2
    x3.Mul(t3, x3)                            // X3 := t3 * X3
    x3.Sub(x3, t1)                            // X3 := X3 - t1
    z3.Mul(t4, z3)                            // Z3 := t4 * Z3
    t1.Mul(t3, t0)                            // t1 := t3 * t0
    z3.Add(z3, t1)                            // Z3 := Z3 + t1

    q.x.Set(x3)
    q.y.Set(y3)
    q.z.Set(z3)
    return q
}

// Double sets q = p + p, and returns q. The points may overlap.
func (q *Point) Double(p *Point) *Point {
    // Complete addition formula for a = -3 from "Complete addition formulas for
    // prime order elliptic curves" (https://eprint.iacr.org/2015/1060), §A.2.
    t0 := new(field.Element).Square(p.x)      // t0 := X ^ 2
    t1 := new(field.Element).Square(p.y)      // t1 := Y ^ 2
    t2 := new(field.Element).Square(p.z)      // t2 := Z ^ 2
    t3 := new(field.Element).Mul(p.x, p.y)    // t3 := X * Y
    t3.Add(t3, t3)                            // t3 := t3 + t3
    z3 := new(field.Element).Mul(p.x, p.z)    // Z3 := X * Z
    z3.Add(z3, z3)                            // Z3 := Z3 + Z3
    y3 := new(field.Element).Mul(p256B(), t2) // Y3 := b * t2
    y3.Sub(y3, z3)                            // Y3 := Y3 - Z3
    x3 := new(field.Element).Add(y3, y3)      // X3 := Y3 + Y3
    y3.Add(x3, y3)                            // Y3 := X3 + Y3
    x3.Sub(t1, y3)                            // X3 := t1 - Y3
    y3.Add(t1, y3)                            // Y3 := t1 + Y3
    y3.Mul(x3, y3)                            // Y3 := X3 * Y3
    x3.Mul(x3, t3)                            // X3 := X3 * t3
    t3.Add(t2, t2)                            // t3 := t2 + t2
    t2.Add(t2, t3)                            // t2 := t2 + t3
    z3.Mul(p256B(), z3)                       // Z3 := b * Z3
    z3.Sub(z3, t2)                            // Z3 := Z3 - t2
    z3.Sub(z3, t0)                            // Z3 := Z3 - t0
    t3.Add(z3, z3)                            // t3 := Z3 + Z3
    z3.Add(z3, t3)                            // Z3 := Z3 + t3
    t3.Add(t0, t0)                            // t3 := t0 + t0
    t0.Add(t3, t0)                            // t0 := t3 + t0
    t0.Sub(t0, t2)                            // t0 := t0 - t2
    t0.Mul(t0, z3)                            // t0 := t0 * Z3
    y3.Add(y3, t0)                            // Y3 := Y3 + t0
    t0.Mul(p.y, p.z)                          // t0 := Y * Z
    t0.Add(t0, t0)                            // t0 := t0 + t0
    z3.Mul(t0, z3)                            // Z3 := t0 * Z3
    x3.Sub(x3, z3)                            // X3 := X3 - Z3
    z3.Mul(t0, t1)                            // Z3 := t0 * t1
    z3.Add(z3, z3)                            // Z3 := Z3 + Z3
    z3.Add(z3, z3)                            // Z3 := Z3 + Z3

    q.x.Set(x3)
    q.y.Set(y3)
    q.z.Set(z3)
    return q
}

// Select sets q to p1 if cond == 1, and to p2 if cond == 0.
func (q *Point) Select(p1, p2 *Point, cond int) *Point {
    q.x.Select(p1.x, p2.x, cond)
    q.y.Select(p1.y, p2.y, cond)
    q.z.Select(p1.z, p2.z, cond)
    return q
}

// A lookupTable holds the first 15 multiples of a point at offset -1, so [1]P
// is at table[0], [15]P is at table[14], and [0]P is implicitly the identity
// point.
type lookupTable [15]*Point

// Select selects the n-th multiple of the table base point into p. It works in
// constant time by iterating over every entry of the table. n must be in [0, 15].
func (table *lookupTable) Select(p *Point, n uint8) {
    if n >= 16 {
        panic("cryptobin/sm2: lookupTable called with out-of-bounds value")
    }
    p.Set(NewPoint())
    for i, f := range table {
        cond := subtle.ConstantTimeByteEq(uint8(i+1), n)
        p.Select(f, p, cond)
    }
}

// ScalarMult sets p = scalar * q, and returns p.
func (p *Point) ScalarMult(q *Point, scalar []byte) (*Point, error) {
    // Compute a lookupTable for the base point q. The explicit NewPoint
    // calls get inlined, letting the allocations live on the stack.
    var table = lookupTable{
        NewPoint(), NewPoint(), NewPoint(),
        NewPoint(), NewPoint(), NewPoint(), NewPoint(),
        NewPoint(), NewPoint(), NewPoint(), NewPoint(),
        NewPoint(), NewPoint(), NewPoint(), NewPoint(),
    }
    table[0].Set(q)
    for i := 1; i < 15; i += 2 {
        table[i].Double(table[i/2])
        table[i+1].Add(table[i], q)
    }

    // Instead of doing the classic double-and-add chain, we do it with a
    // four-bit window: we double four times, and then add [0-15]P.
    t := NewPoint()
    p.Set(NewPoint())
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

var p256GeneratorTable *[p256ElementLength * 2]lookupTable
var p256GeneratorTableOnce sync.Once

// generatorTable returns a sequence of lookupTables. The first table contains
// multiples of G. Each successive table is the previous table doubled four
// times.
func (p *Point) generatorTable() *[p256ElementLength * 2]lookupTable {
    p256GeneratorTableOnce.Do(func() {
        p256GeneratorTable = new([p256ElementLength * 2]lookupTable)
        base := NewPoint().SetGenerator()
        for i := 0; i < p256ElementLength*2; i++ {
            p256GeneratorTable[i][0] = NewPoint().Set(base)
            for j := 1; j < 15; j++ {
                p256GeneratorTable[i][j] = NewPoint().Add(p256GeneratorTable[i][j-1], base)
            }
            base.Double(base)
            base.Double(base)
            base.Double(base)
            base.Double(base)
        }
    })
    return p256GeneratorTable
}

// ScalarBaseMult sets p = scalar * B, where B is the canonical generator, and
// returns p.
func (p *Point) ScalarBaseMult(scalar []byte) (*Point, error) {
    if len(scalar) != p256ElementLength {
        return nil, errors.New("cryptobin/sm2: invalid scalar length")
    }
    tables := p.generatorTable()

    // This is also a scalar multiplication with a four-bit window like in
    // ScalarMult, but in this case the doublings are precomputed. The value
    // [windowValue]G added at iteration k would normally get doubled
    // (totIterations-k)×4 times, but with a larger precomputation we can
    // instead add [2^((totIterations-k)×4)][windowValue]G and avoid the
    // doublings between iterations.
    t := NewPoint()
    p.Set(NewPoint())
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

// p256Sqrt sets e to a square root of x. If x is not a square, p256Sqrt returns
// false and e is unchanged. e and x can overlap.
func p256Sqrt(e, x *field.Element) (isSquare bool) {
    candidate := new(field.Element)
    p256SqrtCandidate(candidate, x)
    square := new(field.Element).Square(candidate)
    if square.Equal(x) != 1 {
        return false
    }
    e.Set(candidate)
    return true
}

// p256SqrtCandidate sets z to a square root candidate for x. z and x must not overlap.
func p256SqrtCandidate(z, x *field.Element) {
    // Since p = 3 mod 4, exponentiation by (p + 1) / 4 yields a square root candidate.
    //
    // The sequence of 13 multiplications and 253 squarings is derived from the
    // following addition chain generated with github.com/mmcloughlin/addchain v0.4.0.
    //
    //	_10      = 2*1
    //	_11      = 1 + _10
    //	_110     = 2*_11
    //	_111     = 1 + _110
    //	_1110    = 2*_111
    //	_1111    = 1 + _1110
    //	_11110   = 2*_1111
    //	_111100  = 2*_11110
    //	_1111000 = 2*_111100
    //	i19      = (_1111000 << 3 + _111100) << 5 + _1111000
    //	x31      = (i19 << 2 + _11110) << 14 + i19 + _111
    //	i42      = x31 << 4
    //	i73      = i42 << 31
    //	i74      = i42 + i73
    //	i171     = (i73 << 32 + i74) << 62 + i74 + _1111
    //	return     (i171 << 32 + 1) << 62
    //
    var t0 = new(field.Element)
    var t1 = new(field.Element)
    var t2 = new(field.Element)
    var t3 = new(field.Element)
    var t4 = new(field.Element)

    z.Square(x)
    z.Mul(x, z)
    z.Square(z)
    t0.Mul(x, z)
    z.Square(t0)
    z.Mul(x, z)
    t2.Square(z)
    t3.Square(t2)
    t1.Square(t3)
    t4.Square(t1)
    for s := 1; s < 3; s++ {
        t4.Square(t4)
    }
    t3.Mul(t3, t4)
    for s := 0; s < 5; s++ {
        t3.Square(t3)
    }
    t1.Mul(t1, t3)
    t3.Square(t1)
    for s := 1; s < 2; s++ {
        t3.Square(t3)
    }
    t2.Mul(t2, t3)
    for s := 0; s < 14; s++ {
        t2.Square(t2)
    }
    t1.Mul(t1, t2)
    t0.Mul(t0, t1)
    for s := 0; s < 4; s++ {
        t0.Square(t0)
    }
    t1.Square(t0)
    for s := 1; s < 31; s++ {
        t1.Square(t1)
    }
    t0.Mul(t0, t1)
    for s := 0; s < 32; s++ {
        t1.Square(t1)
    }
    t1.Mul(t0, t1)
    for s := 0; s < 62; s++ {
        t1.Square(t1)
    }
    t0.Mul(t0, t1)
    z.Mul(z, t0)
    for s := 0; s < 32; s++ {
        z.Square(z)
    }
    z.Mul(x, z)
    for s := 0; s < 62; s++ {
        z.Square(z)
    }
}
