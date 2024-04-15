package brainpool

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

func Test_Brainpool(t *testing.T) {
    tests := []testData{
        {"P160t1", P160t1()},
        {"P160r1", P160r1()},
        {"P192t1", P192t1()},
        {"P192r1", P192r1()},
        {"P224t1", P224t1()},
        {"P224r1", P224r1()},

        {"P256t1", P256t1()},
        {"P256r1", P256r1()},
        {"P320t1", P320t1()},
        {"P320r1", P320r1()},
        {"P384t1", P384t1()},
        {"P384r1", P384r1()},
        {"P512t1", P512t1()},
        {"P512r1", P512r1()},
    }

    for _, c := range tests {
        t.Run(c.name, func(t *testing.T) {
            testCurve(t, c.curve)
        })
    }
}
