package gost

import (
    "bytes"
    "testing"
    "crypto/rand"
)

func Test_ECDH(t *testing.T) {
    c := CurveIdGostR34102001TestParamSet()

    priv1, err := GenerateKey(rand.Reader, c)
    if err != nil {
        t.Fatal(err)
    }
    pub1 := &priv1.PublicKey

    priv2, err := GenerateKey(rand.Reader, c)
    if err != nil {
        t.Fatal(err)
    }
    pub2 := &priv2.PublicKey

    key1, _ := ECDH(priv1, pub2)
    key2, _ := ECDH(priv2, pub1)

    if !bytes.Equal(key1, key2) {
        t.Error("key1 is equal key2")
    }
}
