package ed448

import (
    "testing"
    "crypto/rand"
)

func Test_Marshal(t *testing.T) {
    public, private, _ := GenerateKey(rand.Reader)

    pubkey, err := MarshalPublicKey(public)
    if err != nil {
        t.Errorf("MarshalPublicKey error: %s", err)
    }

    parsedPub, err := ParsePublicKey(pubkey)
    if err != nil {
        t.Errorf("ParsePublicKey error: %s", err)
    }

    prikey, err := MarshalPrivateKey(private)
    if err != nil {
        t.Errorf("MarshalPrivateKey error: %s", err)
    }

    parsedPri, err := ParsePrivateKey(prikey)
    if err != nil {
        t.Errorf("ParsePrivateKey error: %s", err)
    }

    if !public.Equal(parsedPub) {
        t.Errorf("parsedPub error")
    }
    if !private.Equal(parsedPri) {
        t.Errorf("parsedPri error")
    }
}
