package kg

import (
    "math/big"
    "crypto/elliptic"
)

// KGCurve is a Curve implementation.
type KGCurve struct {
    Name    string
    P       *big.Int // the order of the underlying field
    N       *big.Int // the order of the base point
    B       *big.Int // the constant of the BitCurve equation
    A       *big.Int // KG Curve A data
    Gx, Gy  *big.Int // (x,y) of the base point
    BitSize int      // the size of the underlying field
}

func (curve *KGCurve) Params() *elliptic.CurveParams {
    cp := new(elliptic.CurveParams)
    cp.Name = curve.Name
    cp.P = curve.P
    cp.N = curve.N
    cp.Gx = curve.Gx
    cp.Gy = curve.Gy
    cp.BitSize = curve.BitSize
    return cp
}

// polynomial returns x³ + ax + b.
func (curve *KGCurve) polynomial(x *big.Int) *big.Int {
    // x³
    x3 := new(big.Int).Mul(x, x)
    x3.Mul(x3, x)

    // ax
    ax := new(big.Int).Mul(curve.A, x)

    // x³ + ax + b
    r := new(big.Int).Add(x3, ax)
    r.Add(r, curve.B)
    r.Mod(r, curve.P)

    return r
}

func (curve *KGCurve) IsOnCurve(x, y *big.Int) bool {
    if x.Sign() == 0 && y.Sign() == 0 {
        return true
    }

    // y² = x³ + ax + b
    y2 := new(big.Int).Mul(y, y)
    y2.Mod(y2, curve.P)

    return curve.polynomial(x).Cmp(y2) == 0
}

func (curve *KGCurve) Add(x1, y1, x2, y2 *big.Int) (*big.Int, *big.Int) {
    if x1.Sign() == 0 && y1.Sign() == 0 {
        return x2, y2
    }
    if x2.Sign() == 0 && y2.Sign() == 0 {
        return x1, y1
    }

    if x1.Cmp(x2) == 0 {
        if y1.Cmp(y2) == 0 {
            return curve.Double(x1, y1)
        }

        return nil, nil
    }

    y2MinusY1 := new(big.Int).Sub(y2, y1)
    x2MinusX1 := new(big.Int).Sub(x2, x1)
    x2MinusX1Inv := new(big.Int).ModInverse(x2MinusX1, curve.P)
    lambda := new(big.Int).Mul(y2MinusY1, x2MinusX1Inv)
    lambda.Mod(lambda, curve.P)

    x3 := new(big.Int).Mul(lambda, lambda)
    x3.Sub(x3, x1)
    x3.Sub(x3, x2)
    x3.Mod(x3, curve.P)

    y3 := new(big.Int).Sub(x1, x3)
    y3.Mul(lambda, y3)
    y3.Sub(y3, y1)
    y3.Mod(y3, curve.P)

    return x3, y3
}

func (curve *KGCurve) Double(x, y *big.Int) (*big.Int, *big.Int) {
    // 3 * x³ + a
    x2 := new(big.Int).Mul(x, x)
    threeX2 := new(big.Int).Mul(big.NewInt(3), x2)
    numerator := new(big.Int).Add(threeX2, curve.A)

    // 2 * y
    twoY := new(big.Int).Mul(big.NewInt(2), y)
    denomInv := new(big.Int).ModInverse(twoY, curve.P)

    // (3 * x³ + a) * (2 * y)
    lambda := new(big.Int).Mul(numerator, denomInv)
    lambda.Mod(lambda, curve.P)

    x3 := new(big.Int).Mul(lambda, lambda)
    x3.Sub(x3, new(big.Int).Mul(big.NewInt(2), x))
    x3.Mod(x3, curve.P)

    y3 := new(big.Int).Sub(x, x3)
    y3.Mul(lambda, y3)
    y3.Sub(y3, y)
    y3.Mod(y3, curve.P)

    return x3, y3
}

func (curve *KGCurve) ScalarMult(x1, y1 *big.Int, k []byte) (*big.Int, *big.Int) {
    if x1.Sign() == 0 && y1.Sign() == 0 {
        return new(big.Int), new(big.Int)
    }

    kInt := new(big.Int).SetBytes(k)

    resultX := new(big.Int)
    resultY := new(big.Int)

    tempX := new(big.Int).Set(x1)
    tempY := new(big.Int).Set(y1)

    for i := 0; i < kInt.BitLen(); i++ {
        if kInt.Bit(i) == 1 {
            if resultX.Sign() == 0 && resultY.Sign() == 0 {
                resultX.Set(tempX)
                resultY.Set(tempY)
            } else {
                resultX, resultY = curve.Add(resultX, resultY, tempX, tempY)
            }
        }

        tempX, tempY = curve.Double(tempX, tempY)
    }

    return resultX, resultY
}

func (curve *KGCurve) ScalarBaseMult(k []byte) (*big.Int, *big.Int) {
    return curve.ScalarMult(curve.Gx, curve.Gy, k)
}

// Marshal converts a point into the form specified in section 4.3.6 of ANSI
// X9.62.
func (curve *KGCurve) Marshal(x, y *big.Int) []byte {
    return Marshal(curve, x, y)
}

// MarshalCompressed converts a point on the curve into the compressed form
// specified in SEC 1, Version 2.0, Section 2.3.3. If the point is not on the
// curve (or is the conventional point at infinity), the behavior is undefined.
func (curve *KGCurve) MarshalCompressed(x, y *big.Int) []byte {
    return MarshalCompressed(curve, x, y)
}

// Unmarshal converts a point, serialised by Marshal, into an x, y pair. On
// error, x = nil.
func (curve *KGCurve) Unmarshal(data []byte) (x, y *big.Int) {
    byteLen := (curve.BitSize + 7) / 8

    if len(data) != 1+2*byteLen {
        return nil, nil
    }
    if data[0] != 4 { // uncompressed form
        return nil, nil
    }

    p := curve.P

    x = new(big.Int).SetBytes(data[1 : 1+byteLen])
    y = new(big.Int).SetBytes(data[1+byteLen:])

    if x.Cmp(p) >= 0 || y.Cmp(p) >= 0 {
        return nil, nil
    }

    if !curve.IsOnCurve(x, y) {
        return nil, nil
    }

    return
}

// UnmarshalCompressed converts a point, serialized by MarshalCompressed, into
// an x, y pair. It is an error if the point is not in compressed form, is not
// on the curve, or is the point at infinity. On error, x = nil.
func (curve *KGCurve) UnmarshalCompressed(data []byte) (x, y *big.Int) {
    byteLen := (curve.BitSize + 7) / 8
    if len(data) != 1+byteLen {
        return nil, nil
    }
    if data[0] != 2 && data[0] != 3 { // compressed form
        return nil, nil
    }

    p := curve.P
    x = new(big.Int).SetBytes(data[1:])
    if x.Cmp(p) >= 0 {
        return nil, nil
    }

    // y² = x³ + ax + b
    y = curve.polynomial(x)
    y = y.ModSqrt(y, p)
    if y == nil {
        return nil, nil
    }

    if byte(y.Bit(0)) != data[0]&1 {
        y.Neg(y).Mod(y, p)
    }

    if !curve.IsOnCurve(x, y) {
        return nil, nil
    }

    return
}

// Marshal converts a point into the form specified in section 4.3.6 of ANSI
// X9.62.
func Marshal(curve elliptic.Curve, x, y *big.Int) []byte {
    panicIfNotOnCurve(curve, x, y)

    byteLen := (curve.Params().BitSize + 7) / 8

    ret := make([]byte, 1+2*byteLen)
    ret[0] = 4 // uncompressed point

    x.FillBytes(ret[1 : 1+byteLen])
    y.FillBytes(ret[1+byteLen : 1+2*byteLen])

    return ret
}

// MarshalCompressed converts a point on the curve into the compressed form
// specified in SEC 1, Version 2.0, Section 2.3.3. If the point is not on the
// curve (or is the conventional point at infinity), the behavior is undefined.
func MarshalCompressed(curve elliptic.Curve, x, y *big.Int) []byte {
    panicIfNotOnCurve(curve, x, y)

    byteLen := (curve.Params().BitSize + 7) / 8

    compressed := make([]byte, 1+byteLen)
    compressed[0] = byte(y.Bit(0)) | 2

    x.FillBytes(compressed[1:])

    return compressed
}

func panicIfNotOnCurve(curve elliptic.Curve, x, y *big.Int) {
    // (0, 0) is the point at infinity by convention. It's ok to operate on it,
    // although IsOnCurve is documented to return false for it. See Issue 37294.
    if x.Sign() == 0 && y.Sign() == 0 {
        return
    }

    if !curve.IsOnCurve(x, y) {
        panic("go-cryptobin/kg: attempted operation on invalid point")
    }
}
