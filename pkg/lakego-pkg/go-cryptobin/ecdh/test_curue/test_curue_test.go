package test_curue

import (
    "fmt"
    "bytes"
    "testing"
    "crypto/rand"
    "encoding/hex"

    "github.com/deatil/go-cryptobin/ecdh"

    cryptobin_test "github.com/deatil/go-cryptobin/tool/test"
)

func hexDecode(t *testing.T, s string) []byte {
    b, err := hex.DecodeString(s)
    if err != nil {
        t.Fatal("invalid hex string:", s)
    }

    return b
}

func TestX448Failure(t *testing.T) {
    identity := hexDecode(t, "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
    lowOrderPoint := hexDecode(t, "0100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
    randomScalar := make([]byte, 56)
    rand.Read(randomScalar)

    t.Run("identity point", func(t *testing.T) { testX448Failure(t, randomScalar, identity) })
    t.Run("low order point", func(t *testing.T) { testX448Failure(t, randomScalar, lowOrderPoint) })
}

func testX448Failure(t *testing.T, private, public []byte) {
    priv, err := X448D().NewPrivateKey(private)
    if err != nil {
        t.Fatal(err)
    }

    pub, err := X448D().NewPublicKey(public)
    if err != nil {
        t.Fatal(err)
    }

    secret, err := priv.ECDH(pub)
    if err == nil {
        t.Error("expected ECDH error")
    }

    if secret != nil {
        t.Errorf("unexpected ECDH output: %x", secret)
    }
}

func TestAllECDH(t *testing.T) {
    testX448ECDH(t, X448D())
}

func testX448ECDH(t *testing.T, curue ecdh.Curve) {
    t.Run(fmt.Sprintf("%s", curue), func(t *testing.T) {
        priv1, err := curue.GenerateKey(rand.Reader)
        if err != nil {
            t.Fatal(err)
        }

        pub1 := priv1.PublicKey()

        // =======

        priv2, err := curue.GenerateKey(rand.Reader)
        if err != nil {
            t.Fatal(err)
        }

        pub2 := priv2.PublicKey()

        // =======

        secret1, err := priv1.ECDH(pub2)
        if err != nil {
            t.Error("expected ECDH1 error: " + err.Error())
        }

        if secret1 == nil {
            t.Errorf("expected ECDH1 nil")
        }

        // =======

        secret2, err := priv2.ECDH(pub1)
        if err != nil {
            t.Error("expected ECDH2 error: " + err.Error())
        }

        if secret2 == nil {
            t.Errorf("expected ECDH2 nil")
        }

        // =======

        if !bytes.Equal(secret1, secret2) {
            t.Error("two ECDH computations came out different")
        }

    })
}

func Test_NistStringEqual(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)

    assertEqual(fmt.Sprintf("%s", X448D()), "X448D", "NistEqual")
}

func TestAllKeyBytes(t *testing.T) {
    testKeyBytes(t, X448D())
}

func testKeyBytes(t *testing.T, curue ecdh.Curve) {
    t.Run(fmt.Sprintf("%s", curue), func(t *testing.T) {
        priv, err := curue.GenerateKey(rand.Reader)
        if err != nil {
            t.Fatal(err)
        }

        pub := priv.PublicKey()

        privBytes := priv.Bytes()
        pubBytes := pub.Bytes()

        if len(privBytes) == 0 {
            t.Error("expected export key Bytes error: priv")
        }
        if len(pubBytes) == 0 {
            t.Error("expected export key Bytes error: pub")
        }

        newPriv, err := curue.NewPrivateKey(privBytes)
        if err != nil {
            t.Error("NewPrivateKey error: " + err.Error())
        }

        newPub, err := curue.NewPublicKey(pubBytes)
        if err != nil {
            t.Error("NewPublicKey error: " + err.Error())
        }

        if !newPriv.Equal(priv) {
            t.Error("bytes make privekey error")
        }
        if !newPub.Equal(pub) {
            t.Error("bytes make privekey error")
        }

    })
}
