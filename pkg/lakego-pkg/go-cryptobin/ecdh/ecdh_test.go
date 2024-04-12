package ecdh_test

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
    priv, err := ecdh.X448().NewPrivateKey(private)
    if err != nil {
        t.Fatal(err)
    }

    pub, err := ecdh.X448().NewPublicKey(public)
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
    testX448ECDH(t, ecdh.P256())
    testX448ECDH(t, ecdh.P384())
    testX448ECDH(t, ecdh.P521())
    testX448ECDH(t, ecdh.X25519())
    testX448ECDH(t, ecdh.X448())

    testX448ECDH(t, ecdh.GmSM2())
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

    assertEqual(fmt.Sprintf("%s", ecdh.P256()), "P-256", "NistEqual")
    assertEqual(fmt.Sprintf("%s", ecdh.P384()), "P-384", "NistEqual")
    assertEqual(fmt.Sprintf("%s", ecdh.P521()), "P-521", "NistEqual")
    assertEqual(fmt.Sprintf("%s", ecdh.X25519()), "X25519", "NistEqual")
    assertEqual(fmt.Sprintf("%s", ecdh.X448()), "X448", "NistEqual")

    assertEqual(fmt.Sprintf("%s", ecdh.GmSM2()), "GmSM2", "NistEqual")
}

func Test_AllKeyBytes(t *testing.T) {
    testKeyBytes(t, ecdh.P256())
    testKeyBytes(t, ecdh.P384())
    testKeyBytes(t, ecdh.P521())
    testKeyBytes(t, ecdh.X25519())
    testKeyBytes(t, ecdh.X448())

    testKeyBytes(t, ecdh.GmSM2())
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

func Test_ECMQV(t *testing.T) {
    aliceSKey, err := ecdh.GmSM2().GenerateKey(rand.Reader)
    if err != nil {
        t.Fatal(err)
    }
    aliceEKey, err := ecdh.GmSM2().GenerateKey(rand.Reader)
    if err != nil {
        t.Fatal(err)
    }

    bobSKey, err := ecdh.GmSM2().GenerateKey(rand.Reader)
    if err != nil {
        t.Fatal(err)
    }
    bobEKey, err := ecdh.GmSM2().GenerateKey(rand.Reader)
    if err != nil {
        t.Fatal(err)
    }

    bobSecret, err := bobSKey.ECMQV(bobEKey, aliceSKey.PublicKey(), aliceEKey.PublicKey())
    if err != nil {
        t.Fatal(err)
    }

    aliceSecret, err := aliceSKey.ECMQV(aliceEKey, bobSKey.PublicKey(), bobEKey.PublicKey())
    if err != nil {
        t.Fatal(err)
    }

    if !aliceSecret.Equal(bobSecret) {
        t.Error("two ECMQV computations came out different")
    }
}

func Test_SM2SharedKey(t *testing.T) {
    aliceSKey, err := ecdh.GmSM2().GenerateKey(rand.Reader)
    if err != nil {
        t.Fatal(err)
    }
    aliceEKey, err := ecdh.GmSM2().GenerateKey(rand.Reader)
    if err != nil {
        t.Fatal(err)
    }

    bobSKey, err := ecdh.GmSM2().GenerateKey(rand.Reader)
    if err != nil {
        t.Fatal(err)
    }
    bobEKey, err := ecdh.GmSM2().GenerateKey(rand.Reader)
    if err != nil {
        t.Fatal(err)
    }

    bobSecret, err := bobSKey.ECMQV(bobEKey, aliceSKey.PublicKey(), aliceEKey.PublicKey())
    if err != nil {
        t.Fatal(err)
    }

    aliceSecret, err := aliceSKey.ECMQV(aliceEKey, bobSKey.PublicKey(), bobEKey.PublicKey())
    if err != nil {
        t.Fatal(err)
    }

    if !aliceSecret.Equal(bobSecret) {
        t.Error("two ECMQV computations came out different")
    }

    bobKey, err := bobSecret.SM2SharedKey(aliceSKey.PublicKey(), bobSKey.PublicKey(), []byte("Alice"), []byte("Bob"), 48)
    if err != nil {
        t.Fatal(err)
    }

    aliceKey, err := aliceSecret.SM2SharedKey(aliceSKey.PublicKey(), bobSKey.PublicKey(), []byte("Alice"), []byte("Bob"), 48)
    if err != nil {
        t.Fatal(err)
    }

    if !bytes.Equal(bobKey, aliceKey) {
        t.Error("two SM2SharedKey computations came out different")
    }
}
