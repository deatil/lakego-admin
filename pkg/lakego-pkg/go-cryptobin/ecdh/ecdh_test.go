package ecdh_test

import (
    "bytes"
    "testing"
    "crypto/rand"
    "encoding/hex"

    "github.com/deatil/go-cryptobin/ecdh"
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
    lowOrderPoint := hexDecode(t, "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd")
    randomScalar := make([]byte, 112)
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

func TestX448ECDH(t *testing.T) {
    t.Run("identity point", func(t *testing.T) {
        randomScalar1 := make([]byte, 112)
        rand.Read(randomScalar1)

        priv1, err := ecdh.X448().NewPrivateKey(randomScalar1)
        if err != nil {
            t.Fatal(err)
        }

        pub1 := priv1.PublicKey()

        // =======

        randomScalar2 := make([]byte, 112)
        rand.Read(randomScalar2)

        priv2, err := ecdh.X448().NewPrivateKey(randomScalar2)
        if err != nil {
            t.Fatal(err)
        }

        pub2 := priv2.PublicKey()

        // =======

        secret1, err := priv1.ECDH(pub2)
        if err == nil {
            t.Error("expected ECDH1 error")
        }

        if secret1 != nil {
            t.Errorf("unexpected ECDH1 output: %x", secret1)
        }

        // =======

        secret2, err := priv2.ECDH(pub1)
        if err == nil {
            t.Error("expected ECDH2 error")
        }

        if secret2 != nil {
            t.Errorf("unexpected ECDH2 output: %x", secret2)
        }

        // =======

        if !bytes.Equal(secret1, secret2) {
            t.Error("two ECDH computations came out different")
        }

    })
}
