package xmss

import (
    "testing"
    "crypto/rand"

    cryptobin_test "github.com/deatil/go-cryptobin/tool/test"
)

func Test_XMSS(t *testing.T) {
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

func Test_XMSSWithName(t *testing.T) {
    assert := cryptobin_test.AssertEqualT(t)

    name := "XMSS-SHA2_10_256"

    prv, pub, err := GenerateKeyWithName(rand.Reader, name)
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

    prvName, err := GetPrivateKeyTypeName(prv)
    if err != nil {
        t.Fatal(err)
    }

    if prvName != name {
        t.Error("XMSS test failed. GetPrivateKeyTypeName error")
    }

    pubName, err := GetPublicKeyTypeName(pub)
    if err != nil {
        t.Fatal(err)
    }

    if pubName != name {
        t.Error("XMSS test failed. GetPublicKeyTypeName error")
    }

    pub2, err := ExportPublicKey(prv)
    if err != nil {
        t.Fatal(err)
    }

    assert(pub2, pub, "XMSS test failed. ExportPublicKey error")
}
