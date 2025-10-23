package kg

import (
    "testing"
    "crypto/rand"
    "crypto/ecdsa"
    "crypto/elliptic"
)

func Test_Interface(t *testing.T) {
    var _ elliptic.Curve = (*KGCurve)(nil)
}

func testCurve(t *testing.T, curve *KGCurve) {
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
    curve *KGCurve
}

func Test_Curve(t *testing.T) {
    tests := []testData{
        {"KG256r1", KG256r1()},
        {"KG384r1", KG384r1()},
    }

    for _, c := range tests {
        t.Run(c.name, func(t *testing.T) {
            testCurve(t, c.curve)
        })
    }
}
