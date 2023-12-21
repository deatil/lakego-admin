package gost_test

import (
    "fmt"
    "testing"
    "crypto/rand"

    "github.com/deatil/go-cryptobin/gost"
)

func TestPkcs1Equal(t *testing.T) {
    testPkcs1OneCurve(t, gost.CurveIdGostR34102001TestParamSet())

    testPkcs1OneCurve(t, gost.CurveIdtc26gost341012256paramSetA())
    testPkcs1OneCurve(t, gost.CurveIdGostR34102001CryptoProAParamSet())
    testPkcs1OneCurve(t, gost.CurveIdGostR34102001CryptoProBParamSet())
    testPkcs1OneCurve(t, gost.CurveIdGostR34102001CryptoProCParamSet())

    testPkcs1OneCurve(t, gost.CurveIdtc26gost341012512paramSetA())
    testPkcs1OneCurve(t, gost.CurveIdtc26gost341012512paramSetB())
    testPkcs1OneCurve(t, gost.CurveIdtc26gost341012512paramSetC())

    testPkcs1OneCurve(t, gost.CurveIdGostR34102001CryptoProXchAParamSet())
    testPkcs1OneCurve(t, gost.CurveIdGostR34102001CryptoProXchBParamSet())
}

func testPkcs1OneCurve(t *testing.T, curue *gost.Curve) {
    t.Run(fmt.Sprintf("PKCS1 %s", curue), func(t *testing.T) {
        priv, err := gost.GenerateKey(rand.Reader, curue)
        if err != nil {
            t.Fatal(err)
        }

        privDer, err := gost.MarshalGostPrivateKey(priv)
        if err != nil {
            t.Fatal(err)
        }

        if len(privDer) == 0 {
            t.Error("expected export key Der error: priv")
        }

        newPriv, err := gost.ParseGostPrivateKey(privDer)
        if err != nil {
            t.Fatal(err)
        }

        if !newPriv.Equal(priv) {
            t.Error("Marshal privekey error")
        }
    })
}
