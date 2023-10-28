package key_test

import (
    "fmt"
    "testing"
    "crypto/rand"

    "github.com/deatil/go-cryptobin/ecdh"
    "github.com/deatil/go-cryptobin/ecdh/key"
)

func TestEqual(t *testing.T) {
    testOneCurve(t, ecdh.P256())
    testOneCurve(t, ecdh.P384())
    testOneCurve(t, ecdh.P521())
    testOneCurve(t, ecdh.X25519())
    testOneCurve(t, ecdh.X448())
}

func testOneCurve(t *testing.T, curue ecdh.Curve) {
    t.Run(fmt.Sprintf("%s", curue), func(t *testing.T) {
        priv, err := curue.GenerateKey(rand.Reader)
        if err != nil {
            t.Fatal(err)
        }

        pub := priv.PublicKey()

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
