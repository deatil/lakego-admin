package bip0340

import (
    "math/big"
)

// Marshal converts a point on the curve into the uncompressed form specified in
// SEC 1, Version 2.0, Section 2.3.3. If the point is not on the curve (or is
// the conventional point at infinity), the behavior is undefined.
func Marshal(curve *CurveParams, x, y *big.Int) []byte {
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
func MarshalCompressed(curve *CurveParams, x, y *big.Int) []byte {
    panicIfNotOnCurve(curve, x, y)
    byteLen := (curve.Params().BitSize + 7) / 8
    compressed := make([]byte, 1+byteLen)
    compressed[0] = byte(y.Bit(0)) | 2
    x.FillBytes(compressed[1:])
    return compressed
}

// Unmarshal converts a point, serialized by Marshal, into an x, y pair. It is
// an error if the point is not in uncompressed form, is not on the curve, or is
// the point at infinity. On error, x = nil.
func Unmarshal(curve *CurveParams, data []byte) (x, y *big.Int) {
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
func UnmarshalCompressed(curve *CurveParams, data []byte) (x, y *big.Int) {
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
    // y² = x³ + 7
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

var p256 *CurveParams

func init() {
    p256 = &CurveParams{
        Name:    "Bip0340-P-256",
        BitSize: 256,
        P:  bigFromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F"),
        N:  bigFromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"),
        Gx: bigFromHex("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"),
        Gy: bigFromHex("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8"),
    }
}

// The following conventions are used, with constants as defined for secp256k1.
// We note that adapting this specification to other elliptic curves is not straightforward
// and can result in an insecure scheme
func P256() *CurveParams {
    return p256
}
