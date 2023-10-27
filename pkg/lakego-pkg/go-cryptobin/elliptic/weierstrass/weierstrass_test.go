package weierstrass

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

func TestP160r1(t *testing.T) {
    testCurve(t, P160r1())
}

func TestP160r2(t *testing.T) {
    testCurve(t, P160r2())
}

func TestP192r1(t *testing.T) {
    testCurve(t, P192r1())
}

