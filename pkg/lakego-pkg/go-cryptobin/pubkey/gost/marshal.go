package gost

import (
    "math/big"
)

// Marshal converts a point on the curve into the uncompressed
func Marshal(curve *Curve, x, y *big.Int) []byte {
    panicIfNotOnCurve(curve, x, y)

    byteLen := curve.PointSize()

    ret := make([]byte, 2*byteLen)

    y.FillBytes(ret[0      :  byteLen])
    x.FillBytes(ret[byteLen:2*byteLen])

    return Reverse(ret)
}

// Unmarshal converts a point, serialized by Marshal, into an x, y pair. It is
// an error if the point is not in uncompressed form, is not on the curve, or is
// the point at infinity. On error, x = nil.
func Unmarshal(curve *Curve, data []byte) (x, y *big.Int) {
    byteLen := curve.PointSize()
    if len(data) != 2*byteLen {
        return nil, nil
    }

    data = Reverse(data)

    y = new(big.Int).SetBytes(data[:byteLen])
    x = new(big.Int).SetBytes(data[byteLen:])

    p := curve.Params().P
    if x.Cmp(p) >= 0 || y.Cmp(p) >= 0 {
        return nil, nil
    }

    if !curve.IsOnCurve(x, y) {
        return nil, nil
    }

    return
}

func panicIfNotOnCurve(curve *Curve, x, y *big.Int) {
    // (0, 0) is the point at infinity by convention. It's ok to operate on it,
    // although IsOnCurve is documented to return false for it. See Issue 37294.
    if x.Sign() == 0 && y.Sign() == 0 {
        return
    }

    if !curve.IsOnCurve(x, y) {
        panic("cryptobin/gost: attempted operation on invalid point")
    }
}
