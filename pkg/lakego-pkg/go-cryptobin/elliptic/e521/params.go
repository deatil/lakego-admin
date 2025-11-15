package e521

import (
    "math/big"
    "crypto/elliptic"
)

type E521Curve struct {
    Name    string
    P       *big.Int
    N       *big.Int
    D       *big.Int
    Gx, Gy  *big.Int
    BitSize int
}

func (curve *E521Curve) Params() *elliptic.CurveParams {
    cp := new(elliptic.CurveParams)
    cp.Name = curve.Name
    cp.P = curve.P
    cp.N = curve.N
    cp.Gx = curve.Gx
    cp.Gy = curve.Gy
    cp.BitSize = curve.BitSize
    return cp
}

// polynomial returns (y² - 1) / (dy² - 1).
func (curve *E521Curve) polynomial(y *big.Int) *big.Int {
    // x² + y² = 1 + dx²y²
    // dx²y² - x² = x²(dy² - 1) = y² - 1
    // x² = (y² - 1) / (dy² - 1)

    // u = y² - 1
    y2 := new(big.Int).Mul(y, y)
    y2.Mod(y2, curve.P)

    u := new(big.Int).Sub(y2, big.NewInt(1))
    u.Mod(u, curve.P)

    // v = dy² - 1
    v := new(big.Int).Mul(y2, curve.D)
    v.Sub(v, big.NewInt(1))
    v.Mod(v, curve.P)

    // x² = u / v
    invV := new(big.Int).ModInverse(v, curve.P)
    if invV == nil {
        return new(big.Int)
    }

    x2 := new(big.Int).Mul(u, invV)
    x2.Mod(x2, curve.P)

    return x2
}

// IsOnCurve reports whether the given (x,y) lies on the curve.
// check equation: x² + y² ≡ 1 + d*x²*y² (mod p),
// so we can check equation: x² = (1 - y²) / (1 - d*y²).
func (curve *E521Curve) IsOnCurve(x, y *big.Int) bool {
    if x.Sign() == 0 && y.Sign() == 0 {
        return true
    }

    x2 := new(big.Int).Mul(x, x)
    x2.Mod(x2, curve.P)

    return curve.polynomial(y).Cmp(x2) == 0
}

// Add returns the sum of (x1,y1) and (x2,y2)
func (curve *E521Curve) Add(x1, y1, x2, y2 *big.Int) (x, y *big.Int) {
    if x1.Sign() == 0 && y1.Sign() == 0 {
        return x2, y2
    }
    if x2.Sign() == 0 && y2.Sign() == 0 {
        return x1, y1
    }

    panicIfNotOnCurve(curve, x1, y1)
    panicIfNotOnCurve(curve, x2, y2)

    x1y2 := new(big.Int).Mul(x1, y2)
    x2y1 := new(big.Int).Mul(x2, y1)

    y1y2 := new(big.Int).Mul(y1, y2)
    x1x2 := new(big.Int).Mul(x1, x2)

    // c = d*x1*x2*y1*y2
    c := new(big.Int).Mul(x1x2, y1y2)
    c.Mul(c, curve.D)
    c.Mod(c, curve.P)

    // x = (x1*y2 + x2*y1) / (d*x1*x2*y1*y2 + 1)
    rx1 := new(big.Int).Add(x1y2, x2y1)
    rx2 := new(big.Int).Add(c, big.NewInt(1))
    invRx2 := new(big.Int).ModInverse(rx2, curve.P)
    if invRx2 == nil {
        return
    }

    x = new(big.Int).Mul(rx1, invRx2)
    x.Mod(x, curve.P)

    // y = (x1*x2 - y1*y2) / (d*x1*x2*y1*y2 - 1)
    ry1 := new(big.Int).Sub(x1x2, y1y2)
    ry2 := new(big.Int).Sub(c, big.NewInt(1))
    invRy2 := new(big.Int).ModInverse(ry2, curve.P)
    if invRx2 == nil {
        return
    }

    y = new(big.Int).Mul(ry1, invRy2)
    y.Mod(y, curve.P)

    // return result (x, y)
    return
}

// Double returns 2*(x,y)
func (curve *E521Curve) Double(x1, y1 *big.Int) (*big.Int, *big.Int) {
    x2 := new(big.Int).Set(x1)
    y2 := new(big.Int).Set(y1)

    return curve.Add(x2, y2, x2, y2)
}

func (curve *E521Curve) ScalarMult(Bx, By *big.Int, k []byte) (*big.Int, *big.Int) {
    x, y := big.NewInt(0), big.NewInt(1)

    Bx2 := new(big.Int).Set(Bx)
    By2 := new(big.Int).Set(By)

    kk := ToBigint(k)
    kk.Mod(kk, curve.N)

    for kk.BitLen() > 0 {
        if kk.Bit(0) == 1 {
            x, y = curve.Add(x, y, Bx2, By2)
        }

        Bx2, By2 = curve.Double(Bx2, By2)
        kk.Rsh(kk, 1)
    }

    return x, y
}

func (curve *E521Curve) ScalarBaseMult(k []byte) (*big.Int, *big.Int) {
    return curve.ScalarMult(curve.Gx, curve.Gy, k)
}

func (curve *E521Curve) Marshal(x, y *big.Int) []byte {
    return Marshal(curve, x, y)
}

// MarshalCompressed compresses Edwards point according to RFC 8032: store sign bit of x
func (curve *E521Curve) MarshalCompressed(x, y *big.Int) []byte {
    return MarshalCompressed(curve, x, y)
}

func (curve *E521Curve) Unmarshal(data []byte) (*big.Int, *big.Int) {
    if len(data) == 0 {
        return nil, nil
    }

    byteLen := (curve.BitSize + 7) / 8
    if len(data) != 1+2*byteLen {
        return nil, nil
    }

    if data[0] != 4 {
        return nil, nil
    }

    x := ToBigint(data[1 : 1+byteLen])
    y := ToBigint(data[1+byteLen:])

    if !curve.IsOnCurve(x, y) {
        return nil, nil
    }

    return x, y
}

// UnmarshalCompressed decompresses a compressed point according to RFC 8032
func (curve *E521Curve) UnmarshalCompressed(data []byte) (*big.Int, *big.Int) {
    byteLen := (curve.BitSize + 7) / 8
    if len(data) != byteLen {
        return nil, nil
    }

    // Clear the sign bit from y data
    yBytes := make([]byte, byteLen)
    copy(yBytes, data)
    yBytes[byteLen-1] &= 0x7F

    y := ToBigint(yBytes)

    // get x2 from y
    x2 := curve.polynomial(y)

    x := new(big.Int).ModSqrt(x2, curve.P)
    if x == nil {
        return nil, nil
    }

    lastBit := (data[byteLen-1] >> 7) & 1

    xBytes := FromBigint(x, byteLen)
    if (xBytes[0] & 1) != lastBit {
        x.Sub(curve.P, x)
        x.Mod(x, curve.P)
    }

    return x, y
}

func Marshal(curve elliptic.Curve, x, y *big.Int) []byte {
    panicIfNotOnCurve(curve, x, y)

    byteLen := (curve.Params().BitSize + 7) / 8
    ret := make([]byte, 1+2*byteLen)
    ret[0] = 4 // uncompressed point

    xBytes := FromBigint(x, byteLen)
    yBytes := FromBigint(y, byteLen)

    copy(ret[1:1+byteLen], xBytes)
    copy(ret[1+byteLen:], yBytes)

    return ret
}

func MarshalCompressed(curve elliptic.Curve, x, y *big.Int) []byte {
    panicIfNotOnCurve(curve, x, y)

    byteLen := (curve.Params().BitSize + 7) / 8

    xBytes := FromBigint(x, byteLen)
    yBytes := FromBigint(y, byteLen)

    compressed := make([]byte, byteLen)
    copy(compressed, yBytes)
    compressed[byteLen-1] |= (xBytes[0] & 1) << 7

    return compressed
}

func Unmarshal(curve elliptic.Curve, data []byte) (*big.Int, *big.Int) {
    if c, ok := curve.(*E521Curve); ok {
        return c.Unmarshal(data)
    }

    return nil, nil
}

func UnmarshalCompressed(curve elliptic.Curve, data []byte) (*big.Int, *big.Int) {
    if c, ok := curve.(*E521Curve); ok {
        return c.UnmarshalCompressed(data)
    }

    return nil, nil
}

func panicIfNotOnCurve(curve elliptic.Curve, x, y *big.Int) {
    // (0, 0) is the point at infinity by convention. It's ok to operate on it,
    // although IsOnCurve is documented to return false for it. See Issue 37294.
    if x.Sign() == 0 && y.Sign() == 0 {
        return
    }

    if !curve.IsOnCurve(x, y) {
        panic("go-cryptobin/e521: attempted operation on invalid point")
    }
}

func ToBigint(b []byte) *big.Int {
    bytes := Reverse(b)
    return new(big.Int).SetBytes(bytes)
}

func FromBigint(n *big.Int, length int) []byte {
    bytes := n.FillBytes(make([]byte, length))
    return Reverse(bytes)
}

// Reverse bytes
func Reverse(b []byte) []byte {
    d := make([]byte, len(b))
    copy(d, b)

    for i, j := 0, len(d)-1; i < j; i, j = i+1, j-1 {
        d[i], d[j] = d[j], d[i]
    }

    return d
}

