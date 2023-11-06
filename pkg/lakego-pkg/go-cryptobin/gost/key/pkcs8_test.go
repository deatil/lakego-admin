package key_test

import (
    "fmt"
    "testing"
    "crypto/rand"

    "github.com/deatil/go-cryptobin/gost"
    "github.com/deatil/go-cryptobin/gost/key"
)

func TestEqual(t *testing.T) {
    testOneCurve(t, gost.CurveIdGostR34102001TestParamSet())

    testOneCurve(t, gost.CurveIdtc26gost341012256paramSetA())
    testOneCurve(t, gost.CurveIdGostR34102001CryptoProAParamSet())
    testOneCurve(t, gost.CurveIdGostR34102001CryptoProBParamSet())
    testOneCurve(t, gost.CurveIdGostR34102001CryptoProCParamSet())

    testOneCurve(t, gost.CurveIdtc26gost341012512paramSetA())
    testOneCurve(t, gost.CurveIdtc26gost341012512paramSetB())
    testOneCurve(t, gost.CurveIdtc26gost341012512paramSetC())

    testOneCurve(t, gost.CurveIdGostR34102001CryptoProXchAParamSet())
    testOneCurve(t, gost.CurveIdGostR34102001CryptoProXchBParamSet())
}

func testOneCurve(t *testing.T, curue *gost.Curve) {
    t.Run(fmt.Sprintf("PKCS8 %s", curue), func(t *testing.T) {
        priv, err := gost.GenerateKey(rand.Reader, curue)
        if err != nil {
            t.Fatal(err)
        }

        pub := priv.Public().(*gost.PublicKey)

        pubDer, err := key.MarshalPublicKey(pub)
        if err != nil {
            t.Fatal(err)
        }
        privDer, err := key.MarshalPrivateKey(priv)
        if err != nil {
            t.Fatal(err)
        }

        if len(privDer) == 0 {
            t.Error("expected export key Der error: priv")
        }
        if len(pubDer) == 0 {
            t.Error("expected export key Der error: pub")
        }

        newPub, err := key.ParsePublicKey(pubDer)
        if err != nil {
            t.Fatal(err)
        }
        newPriv, err := key.ParsePrivateKey(privDer)
        if err != nil {
            t.Fatal(err)
        }

        if !newPriv.Equal(priv) {
            t.Error("Marshal privekey error")
        }
        if !newPub.Equal(pub) {
            t.Error("Marshal public error")
        }
    })
}
