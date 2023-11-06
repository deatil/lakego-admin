package gost

import (
    "io"
    "testing"
    "crypto"
    "crypto/rand"
)

func Test_SignerInterface(t *testing.T) {
    c := CurveIdGostR34102001TestParamSet()

    priv, err := GenerateKey(rand.Reader, c)
    if err != nil {
        t.Fatal(err)
    }

    pub := &priv.PublicKey

    var _ crypto.Signer = priv
    var _ crypto.PublicKey = pub
}

func Test_Sign(t *testing.T) {
    message := make([]byte, 32)
    _, err := io.ReadFull(rand.Reader, message)
    if err != nil {
        t.Fatal(err)
    }

    priv, err := GenerateKey(rand.Reader, CurveIdGostR34102001TestParamSet())
    if err != nil {
        t.Fatal(err)
    }

    pub := &priv.PublicKey

    signed, err := priv.Sign(rand.Reader, message, nil)
    if err != nil {
        t.Fatal(err)
    }

    valid, err := pub.Verify(message, signed)
    if err != nil {
        t.Fatal(err)
    }

    if !valid {
        t.Error("Verify: valid error")
    }
}

func Test_SignASN1(t *testing.T) {
    message := make([]byte, 32)
    _, err := io.ReadFull(rand.Reader, message)
    if err != nil {
        t.Fatal(err)
    }

    priv, err := GenerateKey(rand.Reader, CurveIdGostR34102001TestParamSet())
    if err != nil {
        t.Fatal(err)
    }

    pub := &priv.PublicKey

    signed, err := priv.SignASN1(rand.Reader, message, nil)
    if err != nil {
        t.Fatal(err)
    }

    valid, err := pub.VerifyASN1(message, signed)
    if err != nil {
        t.Fatal(err)
    }

    if !valid {
        t.Error("VerifyASN1: valid error")
    }
}

func Test_Sign_Func(t *testing.T) {
    message := make([]byte, 32)
    _, err := io.ReadFull(rand.Reader, message)
    if err != nil {
        t.Fatal(err)
    }

    priv, err := GenerateKey(rand.Reader, CurveIdGostR34102001TestParamSet())
    if err != nil {
        t.Fatal(err)
    }

    pub := &priv.PublicKey

    signed, err := Sign(rand.Reader, priv, message)
    if err != nil {
        t.Fatal(err)
    }

    valid, err := Verify(pub, message, signed)
    if err != nil {
        t.Fatal(err)
    }

    if !valid {
        t.Error("Verify: valid error")
    }
}

func Test_SignASN1_Func(t *testing.T) {
    message := make([]byte, 32)
    _, err := io.ReadFull(rand.Reader, message)
    if err != nil {
        t.Fatal(err)
    }

    priv, err := GenerateKey(rand.Reader, CurveIdGostR34102001TestParamSet())
    if err != nil {
        t.Fatal(err)
    }

    pub := &priv.PublicKey

    signed, err := SignASN1(rand.Reader, priv, message)
    if err != nil {
        t.Fatal(err)
    }

    valid, err := VerifyASN1(pub, message, signed)
    if err != nil {
        t.Fatal(err)
    }

    if !valid {
        t.Error("VerifyASN1: valid error")
    }
}
