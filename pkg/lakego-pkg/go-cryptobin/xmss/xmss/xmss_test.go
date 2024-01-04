package xmss

import (
    "testing"
    "crypto/rand"
)

func Test_XMSS(t *testing.T) {
    t.Parallel()
    oid := uint32(0x00000001)

    prv, pub, err := GenerateKey(rand.Reader, oid)
    if err != nil {
        t.Fatal(err)
    }

    msg := make([]byte, 32)
    rand.Read(msg)

    sig, err := Sign(prv, msg)
    if err != nil {
        t.Fatal(err)
    }

    m := make([]byte, len(sig))

    if !Verify(pub, m, sig) {
        t.Error("XMSS test failed. Verification does not match")
    }
}
