package ecdsa_test

import (
    "fmt"
    "testing"
    "crypto/rand"
    "crypto/ecdsa"
    "crypto/elliptic"
    "encoding/asn1"

    cryptobin_ecdsa "github.com/deatil/go-cryptobin/ecdsa"
    cryptobin_koblitz "github.com/deatil/go-cryptobin/elliptic/koblitz"
)

func TestEqual(t *testing.T) {
    testOneCurve(t, elliptic.P224())
    testOneCurve(t, elliptic.P256())
    testOneCurve(t, elliptic.P384())
    testOneCurve(t, elliptic.P521())

    testOneCurve(t, cryptobin_koblitz.P192k1())
}

func testOneCurve(t *testing.T, curue elliptic.Curve) {
    t.Run(fmt.Sprintf("%s", curue), func(t *testing.T) {
        priv, err := ecdsa.GenerateKey(curue, rand.Reader)
        if err != nil {
            t.Fatal(err)
        }

        pub := priv.Public().(*ecdsa.PublicKey)

        pubDer, err := cryptobin_ecdsa.MarshalPublicKey(pub)
        if err != nil {
            t.Fatal(err)
        }
        privDer, err := cryptobin_ecdsa.MarshalPrivateKey(priv)
        if err != nil {
            t.Fatal(err)
        }

        if len(privDer) == 0 {
            t.Error("expected export key Der error: priv")
        }
        if len(pubDer) == 0 {
            t.Error("expected export key Der error: pub")
        }

        newPub, err := cryptobin_ecdsa.ParsePublicKey(pubDer)
        if err != nil {
            t.Fatal(err)
        }
        newPriv, err := cryptobin_ecdsa.ParsePrivateKey(privDer)
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

var (
    // 测试 OID，非正确 OID
    oidPublicKeyP192k1Test = asn1.ObjectIdentifier{1, 9, 107, 123, 666}
)

func init() {
    cryptobin_ecdsa.AddNamedCurve(cryptobin_koblitz.P192k1(), oidPublicKeyP192k1Test)
}
