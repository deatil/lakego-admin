package ecc

import (
    "io"
    "testing"
    "crypto/rand"
    "crypto/ecdsa"
    "crypto/elliptic"

    "github.com/deatil/go-cryptobin/elliptic/secp256k1"
)

func Test_Encrypt(t *testing.T) {
    test_Encrypt(t, secp256k1.S256())
    test_Encrypt(t, elliptic.P256())
    test_Encrypt(t, elliptic.P384())
    test_Encrypt(t, elliptic.P521())
}

func test_Encrypt(t *testing.T, cu elliptic.Curve) {
    message := make([]byte, 32)
    _, err := io.ReadFull(rand.Reader, message)
    if err != nil {
        t.Fatal(err)
    }

    priv, err := GenerateKey(rand.Reader, cu, nil)
    if err != nil {
        t.Fatal(err)
    }

    pub := &priv.PublicKey

    endata, err := Encrypt(rand.Reader, pub, message, nil, nil)
    if err != nil {
        t.Fatal(err)
    }

    dedata, err := priv.Decrypt(endata, nil, nil)
    if err != nil {
        t.Fatal(err)
    }

    if string(dedata) != string(message) {
        t.Error("Decrypt error")
    }
}

func Test_Encrypt2(t *testing.T) {
    test_Encrypt2(t, secp256k1.S256())
    test_Encrypt2(t, elliptic.P256())
    test_Encrypt2(t, elliptic.P384())
    test_Encrypt2(t, elliptic.P521())
}

func test_Encrypt2(t *testing.T, cu elliptic.Curve) {
    message := make([]byte, 32)
    _, err := io.ReadFull(rand.Reader, message)
    if err != nil {
        t.Fatal(err)
    }

    privateKey, err := ecdsa.GenerateKey(cu, rand.Reader)
    if err != nil {
        t.Fatal(err)
    }

    publicKey := &privateKey.PublicKey

    priv := ImportECDSAPrivateKey(privateKey)
    pub := ImportECDSAPublicKey(publicKey)

    endata, err := Encrypt(rand.Reader, pub, message, nil, nil)
    if err != nil {
        t.Fatal(err)
    }

    dedata, err := priv.Decrypt(endata, nil, nil)
    if err != nil {
        t.Fatal(err)
    }

    if string(dedata) != string(message) {
        t.Error("Decrypt error")
    }
}
