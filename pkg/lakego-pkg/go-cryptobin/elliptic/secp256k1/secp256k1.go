// Package secp256k1 implements the standard secp256k1 elliptic curve over prime fields.
package secp256k1

import (
    "sync"
    "math/big"
    "crypto/elliptic"

    "github.com/deatil/go-cryptobin/elliptic/curve256k1"
)

var initonce sync.Once
var curve secp256k1

func initCurve() {
    // SEC 2 (Draft) Ver. 2.0 2.4 Recommended 256-bit Elliptic Curve Domain Parameters over Fp
    // http://www.secg.org/sec2-v2.pdf
    curve.params = &elliptic.CurveParams{
        Name:    "secp256k1",
        BitSize: 256,
        P:       bigHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F"),
        N:       bigHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"),
        B:       bigHex("0000000000000000000000000000000000000000000000000000000000000007"),
        Gx:      bigHex("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"),
        Gy:      bigHex("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8"),
    }
}

func bigHex(s string) *big.Int {
    i, ok := new(big.Int).SetString(s, 16)
    if !ok {
        panic("secp256k1: failed to parse hex")
    }
    return i
}

// Curve returns the standard secp256k1 elliptic curve.
//
// Multiple invocations of this function will return the same value, so it can be used for equality checks and switch statements.
//
// The cryptographic operations are implemented using constant-time algorithms.
func Curve() elliptic.Curve {
    initonce.Do(initCurve)
    return &curve
}

var S256 = Curve

var _ elliptic.Curve = (*secp256k1)(nil)

type secp256k1 struct {
    params *elliptic.CurveParams
}

// Params returns the parameters for the curve.
func (crv *secp256k1) Params() *elliptic.CurveParams {
    return crv.params
}

// IsOnCurve reports whether the given (x,y) lies on the curve.
func (crv *secp256k1) IsOnCurve(x, y *big.Int) bool {
    var p curve256k1.Point
    if _, err := p.NewPoint(x, y); err != nil {
        return false
    }
    return curve256k1.IsOnCurve(&p)
}

// Add returns the sum of (x1,y1) and (x2,y2)
func (crv *secp256k1) Add(x1, y1, x2, y2 *big.Int) (x, y *big.Int) {
    var p1, p2, p3 curve256k1.Point
    var pj1, pj2, pj3 curve256k1.PointJacobian
    if _, err := p1.NewPoint(x1, y1); err != nil {
        panic("invalid point")
    }
    if _, err := p2.NewPoint(x2, y2); err != nil {
        panic("invalid point")
    }
    pj1.FromAffine(&p1)
    pj2.FromAffine(&p2)
    pj3.Add(&pj1, &pj2)
    p3.FromJacobian(&pj3)
    return p3.ToBig(new(big.Int), new(big.Int))
}

// Double returns 2*(x,y)
func (crv *secp256k1) Double(x1, y1 *big.Int) (x, y *big.Int) {
    var p1, p3 curve256k1.Point
    var pj1, pj3 curve256k1.PointJacobian
    if _, err := p1.NewPoint(x1, y1); err != nil {
        panic("invalid point")
    }
    pj1.FromAffine(&p1)
    pj3.Double(&pj1)
    p3.FromJacobian(&pj3)
    return p3.ToBig(new(big.Int), new(big.Int))
}

// ScalarMult returns k*(Bx,By) where k is a number in big-endian form.
func (crv *secp256k1) ScalarMult(Bx, By *big.Int, k []byte) (x, y *big.Int) {
    var B, ret curve256k1.Point
    var Bj, retj curve256k1.PointJacobian
    if _, err := B.NewPoint(Bx, By); err != nil {
        panic("invalid point")
    }
    Bj.FromAffine(&B)
    retj.ScalarMult(&Bj, k)
    ret.FromJacobian(&retj)
    return ret.ToBig(new(big.Int), new(big.Int))
}

// ScalarBaseMult returns k*G, where G is the base point of the group
// and k is an integer in big-endian form.
func (crv *secp256k1) ScalarBaseMult(k []byte) (x, y *big.Int) {
    var ret curve256k1.Point
    var retj curve256k1.PointJacobian
    retj.ScalarBaseMult(k)
    ret.FromJacobian(&retj)
    return ret.ToBig(new(big.Int), new(big.Int))
}

// CombinedMult returns [s1]G + [s2]P where G is the generator.
// It's used through an interface upgrade in crypto/ecdsa.
func (crv *secp256k1) CombinedMult(Px, Py *big.Int, s1, s2 []byte) (x, y *big.Int) {
    // calculate [s1]G
    var retj1 curve256k1.PointJacobian
    retj1.ScalarBaseMult(s1)

    var B curve256k1.Point
    var Bj, retj2 curve256k1.PointJacobian
    if _, err := B.NewPoint(Px, Py); err != nil {
        panic("invalid point")
    }

    // calculate [s2]P
    Bj.FromAffine(&B)
    retj2.ScalarMult(&Bj, s2)

    // add them
    var ret curve256k1.Point
    retj1.Add(&retj1, &retj2)
    ret.FromJacobian(&retj1)
    return ret.ToBig(new(big.Int), new(big.Int))
}

// polynomial returns x3 + 7.
func (crv *secp256k1) polynomial(x *big.Int) *big.Int {
    x3 := new(big.Int).Mul(x, x)
    x3.Mul(x3, x)

    b := big.NewInt(7)

    x3.Add(x3, b)
    x3.Mod(x3, crv.Params().P)

    return x3
}

// Unmarshal implements elliptic.Unmarshal.
func (crv *secp256k1) Unmarshal(data []byte) (x, y *big.Int) {
    byteLen := (crv.Params().BitSize + 7) / 8
    if len(data) != 1+2*byteLen {
        return nil, nil
    }
    if data[0] != 4 { // uncompressed form
        return nil, nil
    }

    p := crv.Params().P
    x = new(big.Int).SetBytes(data[1 : 1+byteLen])
    y = new(big.Int).SetBytes(data[1+byteLen:])

    if x.Cmp(p) >= 0 || y.Cmp(p) >= 0 {
        return nil, nil
    }
    if !crv.IsOnCurve(x, y) {
        return nil, nil
    }

    return
}

// UnmarshalCompressed implements elliptic.UnmarshalCompressed.
func (crv *secp256k1) UnmarshalCompressed(data []byte) (x, y *big.Int) {
    byteLen := (crv.Params().BitSize + 7) / 8
    if len(data) != 1+byteLen {
        return nil, nil
    }
    if data[0] != 2 && data[0] != 3 { // compressed form
        return nil, nil
    }

    p := crv.Params().P
    x = new(big.Int).SetBytes(data[1:])
    if x.Cmp(p) >= 0 {
        return nil, nil
    }

    // y² = x3 + 7
    y = crv.polynomial(x)
    y = y.ModSqrt(y, p)
    if y == nil {
        return nil, nil
    }

    if byte(y.Bit(0)) != data[0]&1 {
        y.Neg(y).Mod(y, p)
    }

    if !crv.IsOnCurve(x, y) {
        return nil, nil
    }

    return
}
