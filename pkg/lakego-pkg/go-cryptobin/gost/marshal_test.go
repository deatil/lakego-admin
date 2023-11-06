package gost

import (
    "testing"
    "crypto/rand"
)

func Test_MarshalPublicKey(t *testing.T) {
    priv, err := GenerateKey(rand.Reader, CurveIdGostR34102001TestParamSet())
    if err != nil {
        t.Fatal(err)
    }

    pub := &priv.PublicKey

    pubkey := MarshalPublicKey(pub)

    newPub, err := UnmarshalPublicKey(pub.Curve, pubkey)
    if err != nil {
        t.Fatal(err)
    }

    if !newPub.Equal(pub) {
        t.Error("PublicKey Equal error")
    }
}

func Test_MarshalPrivateKey(t *testing.T) {
    priv, err := GenerateKey(rand.Reader, CurveIdGostR34102001TestParamSet())
    if err != nil {
        t.Fatal(err)
    }

    privkey := MarshalPrivateKey(priv)

    newPriv, err := UnmarshalPrivateKey(priv.Curve, privkey)
    if err != nil {
        t.Fatal(err)
    }

    if !newPriv.Equal(priv) {
        t.Error("PrivateKey Equal error")
    }
}
