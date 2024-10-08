package bign

import (
    "errors"
    "math/big"
    "crypto/elliptic"
)

// bignPoint is a generic constraint for the bign Point types.
type bignPoint[T any] interface {
    Bytes() []byte
    SetBytes([]byte) (T, error)
    Add(T, T) T
    Double(T) T
    ScalarMult(T, []byte) (T, error)
    ScalarBaseMult([]byte) (T, error)
}

// bignCurve is a Curve implementation based on a bign Point.
type bignCurve[Point bignPoint[Point]] struct {
    newPoint func() Point
    params   *elliptic.CurveParams
}

func (curve *bignCurve[Point]) Params() *elliptic.CurveParams {
    return curve.params
}

func (curve *bignCurve[Point]) IsOnCurve(x, y *big.Int) bool {
    // IsOnCurve is documented to reject (0, 0), the conventional point at
    // infinity, which however is accepted by pointFromAffine.
    if x.Sign() == 0 && y.Sign() == 0 {
        return false
    }
    _, err := curve.pointFromAffine(x, y)
    return err == nil
}

func (curve *bignCurve[Point]) pointFromAffine(x, y *big.Int) (p Point, err error) {
    // (0, 0) is by convention the point at infinity, which can't be represented
    // in affine coordinates. See Issue 37294.
    if x.Sign() == 0 && y.Sign() == 0 {
        return curve.newPoint(), nil
    }
    // Reject values that would not get correctly encoded.
    if x.Sign() < 0 || y.Sign() < 0 {
        return p, errors.New("negative coordinate")
    }
    if x.BitLen() > curve.params.BitSize || y.BitLen() > curve.params.BitSize {
        return p, errors.New("overflowing coordinate")
    }
    // Encode the coordinates and let SetBytes reject invalid points.
    byteLen := (curve.params.BitSize + 7) / 8
    buf := make([]byte, 1+2*byteLen)
    buf[0] = 4 // uncompressed point
    x.FillBytes(buf[1 : 1+byteLen])
    y.FillBytes(buf[1+byteLen : 1+2*byteLen])
    return curve.newPoint().SetBytes(buf)
}

func (curve *bignCurve[Point]) pointToAffine(p Point) (x, y *big.Int) {
    out := p.Bytes()
    if len(out) == 1 && out[0] == 0 {
        // This is the encoding of the point at infinity, which the affine
        // coordinates API represents as (0, 0) by convention.
        return new(big.Int), new(big.Int)
    }
    byteLen := (curve.params.BitSize + 7) / 8
    x = new(big.Int).SetBytes(out[1 : 1+byteLen])
    y = new(big.Int).SetBytes(out[1+byteLen:])
    return x, y
}

func (curve *bignCurve[Point]) Add(x1, y1, x2, y2 *big.Int) (*big.Int, *big.Int) {
    p1, err := curve.pointFromAffine(x1, y1)
    if err != nil {
        panic("crypto/elliptic: Add was called on an invalid point")
    }
    p2, err := curve.pointFromAffine(x2, y2)
    if err != nil {
        panic("crypto/elliptic: Add was called on an invalid point")
    }
    return curve.pointToAffine(p1.Add(p1, p2))
}

func (curve *bignCurve[Point]) Double(x1, y1 *big.Int) (*big.Int, *big.Int) {
    p, err := curve.pointFromAffine(x1, y1)
    if err != nil {
        panic("crypto/elliptic: Double was called on an invalid point")
    }
    return curve.pointToAffine(p.Double(p))
}

// normalizeScalar brings the scalar within the byte size of the order of the
// curve, as expected by the bign scalar multiplication functions.
func (curve *bignCurve[Point]) normalizeScalar(scalar []byte) []byte {
    byteSize := (curve.params.N.BitLen() + 7) / 8
    if len(scalar) == byteSize {
        return scalar
    }
    s := new(big.Int).SetBytes(scalar)
    if len(scalar) > byteSize {
        s.Mod(s, curve.params.N)
    }
    out := make([]byte, byteSize)
    return s.FillBytes(out)
}

func (curve *bignCurve[Point]) ScalarMult(Bx, By *big.Int, scalar []byte) (*big.Int, *big.Int) {
    p, err := curve.pointFromAffine(Bx, By)
    if err != nil {
        panic("crypto/elliptic: ScalarMult was called on an invalid point")
    }
    scalar = curve.normalizeScalar(scalar)
    p, err = p.ScalarMult(p, scalar)
    if err != nil {
        panic("crypto/elliptic: bign rejected normalized scalar")
    }
    return curve.pointToAffine(p)
}

func (curve *bignCurve[Point]) ScalarBaseMult(scalar []byte) (*big.Int, *big.Int) {
    scalar = curve.normalizeScalar(scalar)
    p, err := curve.newPoint().ScalarBaseMult(scalar)
    if err != nil {
        panic("crypto/elliptic: bign rejected normalized scalar")
    }
    return curve.pointToAffine(p)
}

// CombinedMult returns [s1]G + [s2]P where G is the generator. It's used
// through an interface upgrade in crypto/ecdsa.
func (curve *bignCurve[Point]) CombinedMult(Px, Py *big.Int, s1, s2 []byte) (x, y *big.Int) {
    s1 = curve.normalizeScalar(s1)
    q, err := curve.newPoint().ScalarBaseMult(s1)
    if err != nil {
        panic("crypto/elliptic: bign rejected normalized scalar")
    }
    p, err := curve.pointFromAffine(Px, Py)
    if err != nil {
        panic("crypto/elliptic: CombinedMult was called on an invalid point")
    }
    s2 = curve.normalizeScalar(s2)
    p, err = p.ScalarMult(p, s2)
    if err != nil {
        panic("crypto/elliptic: bign rejected normalized scalar")
    }
    return curve.pointToAffine(p.Add(p, q))
}

func (curve *bignCurve[Point]) Unmarshal(data []byte) (x, y *big.Int) {
    if len(data) == 0 || data[0] != 4 {
        return nil, nil
    }
    // Use SetBytes to check that data encodes a valid point.
    _, err := curve.newPoint().SetBytes(data)
    if err != nil {
        return nil, nil
    }
    // We don't use pointToAffine because it involves an expensive field
    // inversion to convert from Jacobian to affine coordinates, which we
    // already have.
    byteLen := (curve.params.BitSize + 7) / 8
    x = new(big.Int).SetBytes(data[1 : 1+byteLen])
    y = new(big.Int).SetBytes(data[1+byteLen:])
    return x, y
}

func (curve *bignCurve[Point]) UnmarshalCompressed(data []byte) (x, y *big.Int) {
    if len(data) == 0 || (data[0] != 2 && data[0] != 3) {
        return nil, nil
    }
    p, err := curve.newPoint().SetBytes(data)
    if err != nil {
        return nil, nil
    }
    return curve.pointToAffine(p)
}
