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
