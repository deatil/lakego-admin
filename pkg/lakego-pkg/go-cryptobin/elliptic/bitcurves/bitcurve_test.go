package bitcurves

import (
    "testing"
    "encoding/hex"
    "crypto/rand"
    "crypto/ecdsa"
    "crypto/elliptic"
)

func fromHex(s string) []byte {
    h, _ := hex.DecodeString(s)
    return h
}

func testCurve(t *testing.T, curve elliptic.Curve) {
    priv, err := ecdsa.GenerateKey(curve, rand.Reader)
    if err != nil {
        t.Fatal(err)
    }

    msg := []byte("test-data test-data test-data test-data test-data test-data test-data test-data")

    r, s, err := ecdsa.Sign(rand.Reader, priv, msg)
    if err != nil {
        t.Fatal(err)
    }

    if !ecdsa.Verify(&priv.PublicKey, msg, r, s) {
        t.Fatal("signature didn't verify.")
    }
}

func Test_All(t *testing.T) {
    t.Run("S160", func(t *testing.T) {
        testCurve(t, S160())
    })
    t.Run("S192", func(t *testing.T) {
        testCurve(t, S192())
    })

    t.Run("S224", func(t *testing.T) {
        testCurve(t, S224())
    })
    t.Run("S256", func(t *testing.T) {
        testCurve(t, S256())
    })
}
