package nums

import (
    "math/big"
    "crypto/elliptic"
)

var _ elliptic.Curve = (*rcurve)(nil)

type rcurve struct {
    twisted elliptic.Curve
    params  *elliptic.CurveParams
    z       *big.Int
    zinv    *big.Int
    z2      *big.Int
    z3      *big.Int
    zinv2   *big.Int
    zinv3   *big.Int
}

var (
    two   = big.NewInt(2)
    three = big.NewInt(3)
)

func newRcurve(twisted elliptic.Curve, params *elliptic.CurveParams, z *big.Int) *rcurve {
    zinv := new(big.Int).ModInverse(z, params.P)

    return &rcurve{
        twisted: twisted,
        params:  params,
        z:       z,
        zinv:    zinv,
        z2:      new(big.Int).Exp(z, two, params.P),
        z3:      new(big.Int).Exp(z, three, params.P),
        zinv2:   new(big.Int).Exp(zinv, two, params.P),
        zinv3:   new(big.Int).Exp(zinv, three, params.P),
    }
}

func (curve *rcurve) toTwisted(x, y *big.Int) (*big.Int, *big.Int) {
    var tx, ty big.Int
    tx.Mul(x, curve.z2)         // tx = (z^2 mod p) * x
    tx.Mod(&tx, curve.params.P) // tx = tx mod p
    ty.Mul(y, curve.z3)         // ty = (z^3 mod p) * y
    ty.Mod(&ty, curve.params.P) // ty = ty mod p
    return &tx, &ty
}

func (curve *rcurve) fromTwisted(tx, ty *big.Int) (*big.Int, *big.Int) {
    var x, y big.Int
    x.Mul(tx, curve.zinv2)    // x = (zinv^2 mod p) * tx
    x.Mod(&x, curve.params.P) // x = x mod p
    y.Mul(ty, curve.zinv3)    // y = (zinv^3 mod p) * ty
    y.Mod(&y, curve.params.P) // y = y mod p
    return &x, &y
}

func (curve *rcurve) Params() *elliptic.CurveParams {
    return curve.params
}

func (curve *rcurve) IsOnCurve(x, y *big.Int) bool {
    return curve.twisted.IsOnCurve(curve.toTwisted(x, y))
}

func (curve *rcurve) Add(x1, y1, x2, y2 *big.Int) (x, y *big.Int) {
    tx1, ty1 := curve.toTwisted(x1, y1)
    tx2, ty2 := curve.toTwisted(x2, y2)
    return curve.fromTwisted(curve.twisted.Add(tx1, ty1, tx2, ty2))
}

func (curve *rcurve) Double(x1, y1 *big.Int) (x, y *big.Int) {
    return curve.fromTwisted(curve.twisted.Double(curve.toTwisted(x1, y1)))
}

func (curve *rcurve) ScalarMult(x1, y1 *big.Int, scalar []byte) (x, y *big.Int) {
    tx1, ty1 := curve.toTwisted(x1, y1)
    return curve.fromTwisted(curve.twisted.ScalarMult(tx1, ty1, scalar))
}

func (curve *rcurve) ScalarBaseMult(scalar []byte) (x, y *big.Int) {
    return curve.fromTwisted(curve.twisted.ScalarBaseMult(scalar))
}
