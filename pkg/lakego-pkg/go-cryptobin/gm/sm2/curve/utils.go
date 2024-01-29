package curve

import (
    "math/big"
    "crypto/elliptic"
)

// Marshal converts a point on the curve into the uncompressed
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

// unmarshaler is implemented by curves with their own constant-time Unmarshal.
//
// There isn't an equivalent interface for Marshal/MarshalCompressed because
// that doesn't involve any mathematical operations, only FillBytes and Bit.
type unmarshaler interface {
    Unmarshal([]byte) (x, y *big.Int)
    UnmarshalCompressed([]byte) (x, y *big.Int)
}

// polynomial func
type unmarshalerPolynomial interface {
    polynomial(x *big.Int) *big.Int
}

// Unmarshal converts a point, serialized by Marshal, into an x, y pair. It is
// an error if the point is not in uncompressed form, is not on the curve, or is
// the point at infinity. On error, x = nil.
func Unmarshal(curve elliptic.Curve, data []byte) (x, y *big.Int) {
    if c, ok := curve.(unmarshaler); ok {
        return c.Unmarshal(data)
    }

    byteLen := (curve.Params().BitSize + 7) / 8
    if len(data) != 1+2*byteLen {
        return nil, nil
    }
    if data[0] != 4 { // uncompressed form
        return nil, nil
    }

    p := curve.Params().P
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
func UnmarshalCompressed(curve elliptic.Curve, data []byte) (x, y *big.Int) {
    if c, ok := curve.(unmarshaler); ok {
        return c.UnmarshalCompressed(data)
    }

    byteLen := (curve.Params().BitSize + 7) / 8
    if len(data) != 1+byteLen {
        return nil, nil
    }

    if data[0] != 2 && data[0] != 3 { // compressed form
        return nil, nil
    }

    p := curve.Params().P
    x = new(big.Int).SetBytes(data[1:])
    if x.Cmp(p) >= 0 {
        return nil, nil
    }

    cu, ok := curve.(unmarshalerPolynomial)
    if !ok {
        return nil, nil
    }

    y = cu.polynomial(x)
    y = new(big.Int).ModSqrt(y, p)

    if byte(y.Bit(0)) != data[0]&1 {
        y.Sub(p, y)
    }

    if !curve.IsOnCurve(x, y) {
        return nil, nil
    }

    return
}

func panicIfNotOnCurve(curve elliptic.Curve, x, y *big.Int) {
    // (0, 0) is the point at infinity by convention. It's ok to operate on it,
    // although IsOnCurve is documented to return false for it. See Issue 37294.
    if x.Sign() == 0 && y.Sign() == 0 {
        return
    }

    if !curve.IsOnCurve(x, y) {
        panic("cryptobin/sm2: attempted operation on invalid point")
    }
}
