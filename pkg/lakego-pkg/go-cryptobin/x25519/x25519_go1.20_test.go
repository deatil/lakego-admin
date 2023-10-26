//go:build go1.20

package x25519

import (
    "crypto/rand"
    "testing"
)

func TestECDH(t *testing.T) {
    pub, priv, err := GenerateKey(rand.Reader)
    if err != nil {
        t.Fatal(err)
    }

    _, err = pub.ECDH()
    if err != nil {
        t.Fatal(err)
    }

    _, err = priv.ECDH()
    if err != nil {
        t.Fatal(err)
    }
}
