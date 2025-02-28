package tom

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

type testData struct {
    name  string
    curve elliptic.Curve
}

func Test_Curve(t *testing.T) {
    tests := []testData{
        {"P256", P256()},
        {"P384", P384()},
        // {"P521", P521()},
    }

    for _, c := range tests {
        t.Run(c.name, func(t *testing.T) {
            testCurve(t, c.curve)
        })
    }
}
