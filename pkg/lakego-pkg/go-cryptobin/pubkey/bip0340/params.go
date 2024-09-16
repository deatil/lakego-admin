package bip0340

import (
    "math/big"
    "crypto/elliptic"
)

// CurveParams contains the parameters of an elliptic curve and also provides
// a generic, non-constant time implementation of Curve.
type CurveParams struct {
    P       *big.Int // the order of the underlying field
    N       *big.Int // the order of the base point
    B       *big.Int // the constant of the curve equation
    Gx, Gy  *big.Int // (x,y) of the base point
    BitSize int      // the size of the underlying field
    Name    string   // the canonical name of the curve
}

func (curve *CurveParams) Params() *elliptic.CurveParams {
    return &elliptic.CurveParams{
        P: curve.P,
        N: curve.N,
        B: curve.B,
        Gx: curve.Gx,
        Gy: curve.Gy,
        BitSize: curve.BitSize,
        Name: curve.Name,
    }
}

// polynomial returns x3 + 7.
func (curve *CurveParams) polynomial(x *big.Int) *big.Int {
    x3 := new(big.Int).Mul(x, x)
    x3.Mul(x3, x)

    b := big.NewInt(7)

    x3.Add(x3, b)
    x3.Mod(x3, curve.P)

    return x3
}

// IsOnCurve implements Curve.IsOnCurve.
func (curve *CurveParams) IsOnCurve(x, y *big.Int) bool {
    if x.Sign() < 0 || x.Cmp(curve.P) >= 0 ||
        y.Sign() < 0 || y.Cmp(curve.P) >= 0 {
        return false
    }

    // y² = x3 + 7
    y2 := new(big.Int).Mul(y, y)
    y2.Mod(y2, curve.P)

    return curve.polynomial(x).Cmp(y2) == 0
}

// Add implements Curve.Add.
func (curve *CurveParams) Add(x1, y1, x2, y2 *big.Int) (*big.Int, *big.Int) {
    if x1.Sign() == 0 || y1.Sign() == 0 {
        return x2, y2
    }
    if x2.Sign() == 0 || y2.Sign() == 0 {
        return x1, y1
    }

    if bigIntEqual(x1, x2) && !bigIntEqual(y1, y2) {
        return new(big.Int), new(big.Int)
    }

    two := big.NewInt(2)
    three := big.NewInt(3)

    p2 := new(big.Int).Set(curve.P)
    p2.Sub(p2, two)

    var lam *big.Int
    if bigIntEqual(x1, x2) && bigIntEqual(y1, y2) {
        lam = new(big.Int).Set(three)
        lam.Mul(lam, x1)
        lam.Mul(lam, x1)

        tmp := new(big.Int).Set(two)
        tmp.Mul(tmp, y1)
        tmp.Exp(tmp, p2, curve.P)

        lam.Mul(lam, tmp)
        lam.Mod(lam, curve.P)
    } else {
        lam = new(big.Int).Set(y2)
        lam.Sub(lam, y1)
        lam.Mod(lam, curve.P)

        tmp := new(big.Int).Set(x2)
        tmp.Sub(tmp, x1)
        tmp.Exp(tmp, p2, curve.P)

        lam.Mul(lam, tmp)
        lam.Mod(lam, curve.P)
    }

    x3 := new(big.Int).Set(lam)
    x3.Mul(x3, lam)
    x3.Sub(x3, x1)
    x3.Sub(x3, x2)
    x3.Mod(x3, curve.P)

    y3 := new(big.Int).Set(lam)

    tmp := new(big.Int).Set(x1)
    tmp.Sub(tmp, x3)

    y3.Mul(y3, tmp)
    y3.Sub(y3, y1)
    y3.Mod(y3, curve.P)

    return x3, y3
}

// Double implements Curve.Double.
func (curve *CurveParams) Double(x1, y1 *big.Int) (*big.Int, *big.Int) {
    panicIfNotOnCurve(curve, x1, y1)

    x2 := new(big.Int).Set(x1)
    y2 := new(big.Int).Set(y1)

    x2, y2 = curve.Add(x2, y2, x2, y2)

    return x2, y2
}

// ScalarMult implements Curve.ScalarMult.
func (curve *CurveParams) ScalarMult(Bx, By *big.Int, k []byte) (*big.Int, *big.Int) {
    panicIfNotOnCurve(curve, Bx, By)

    x, y := new(big.Int), new(big.Int)

    Bx2 := new(big.Int).Set(Bx)
    By2 := new(big.Int).Set(By)

    kk := new(big.Int).SetBytes(k)

    for i := 0; i < 256; i++ {
        kk2 := new(big.Int).Set(kk)
        kk2.Rsh(kk2, uint(i))
        kk2.And(kk2, one)
        if kk2.Cmp(one) == 0 {
            x, y = curve.Add(x, y, Bx2, By2)
        }

        Bx2, By2 = curve.Add(Bx2, By2, Bx2, By2)
    }

    return x, y
}

// ScalarBaseMult implements Curve.ScalarBaseMult.
func (curve *CurveParams) ScalarBaseMult(k []byte) (*big.Int, *big.Int) {
    return curve.ScalarMult(curve.Gx, curve.Gy, k)
}

func panicIfNotOnCurve(curve elliptic.Curve, x, y *big.Int) {
    // (0, 0) is the point at infinity by convention. It's ok to operate on it,
    // although IsOnCurve is documented to return false for it. See Issue 37294.
    if x.Sign() == 0 && y.Sign() == 0 {
        return
    }

    if !curve.IsOnCurve(x, y) {
        panic("crypto/elliptic: attempted operation on invalid point")
    }
}
