// Package secp256k1 implements the standard secp256k1 elliptic curve over prime fields.
package secp256k1

import (
    "sync"
    "math/big"
    "encoding/asn1"
    "crypto/elliptic"
)

var (
    OIDNamedCurveSecp256k1 = asn1.ObjectIdentifier{1, 3, 132, 0, 10}
)

var initonce sync.Once
var curve secp256k1

func initAll() {
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

// Curve returns the standard secp256k1 elliptic curve.
//
// Multiple invocations of this function will return the same value, so it can be used for equality checks and switch statements.
//
// The cryptographic operations are implemented using constant-time algorithms.
func Curve() elliptic.Curve {
    initonce.Do(initAll)
    return &curve
}

func S256() elliptic.Curve {
    return Curve()
}

func bigHex(s string) *big.Int {
    i, ok := new(big.Int).SetString(s, 16)
    if !ok {
        panic("secp256k1: failed to parse hex")
    }

    return i
}
