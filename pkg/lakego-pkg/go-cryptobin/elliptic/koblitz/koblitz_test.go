package koblitz

import (
    "testing"
    "crypto/rand"
    "crypto/ecdsa"
    "crypto/elliptic"
)

func testCurve(t *testing.T, curve elliptic.Curve) {
    priv, err := ecdsa.GenerateKey(curve, rand.Reader)
    if err != nil {
        t.Fatal(err)
    }

    msg := []byte("test")
    r, s, err := ecdsa.Sign(rand.Reader, priv, msg)
    if err != nil {
        t.Fatal(err)
    }

    if !ecdsa.Verify(&priv.PublicKey, msg, r, s) {
        t.Fatal("signature didn't verify.")
    }
}

func TestP160k1(t *testing.T) {
    testCurve(t, P160k1())
}

func TestP192k1(t *testing.T) {
    testCurve(t, P192k1())
}

func TestP224k1(t *testing.T) {
    testCurve(t, P224k1())
}

func TestP256k1(t *testing.T) {
    testCurve(t, P256k1())
}
