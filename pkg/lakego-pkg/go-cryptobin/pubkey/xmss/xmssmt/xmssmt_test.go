package xmssmt

import (
    "testing"
    "crypto/rand"
    "encoding/hex"

    "github.com/deatil/go-cryptobin/pubkey/xmss"
    cryptobin_test "github.com/deatil/go-cryptobin/tool/test"
)

func Test_XMSSMT(t *testing.T) {
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
        t.Error("XMSSMT test failed. Verification does not match")
    }
}

func Test_XMSSMTWithName(t *testing.T) {
    assert := cryptobin_test.AssertEqualT(t)

    name := "XMSSMT-SHA2_40/4_192"

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
        t.Error("XMSSMT test failed. Verification does not match")
    }

    prvName, err := GetPrivateKeyTypeName(prv)
    if err != nil {
        t.Fatal(err)
    }

    if prvName != name {
        t.Error("XMSSMT test failed. GetPrivateKeyTypeName error")
    }

    pubName, err := GetPublicKeyTypeName(pub)
    if err != nil {
        t.Fatal(err)
    }

    if pubName != name {
        t.Error("XMSSMT test failed. GetPublicKeyTypeName error")
    }

    pub2, err := ExportPublicKey(prv)
    if err != nil {
        t.Fatal(err)
    }

    assert(pub2, pub, "XMSSMT test failed. ExportPublicKey error")
}

func Test_XMSSMT_Check(t *testing.T) {
    prv := "00000002000000be9b3820ffc50b10c91ebe5a2f294ce90d83ba749e8c7f1be0130c60d4bcdf79e0c3c526d88df2d27bb00c706072a1402654312c5b0224e04d7744a8aa1f50222dec0eab8dc64d1ee93d1fa7d5ef486c21e1582887ac2b85653c4a0743b9273697e9d9fa6f4926e3e1ecae02044e70bb855c86820bc8d62cf2d8fa997aa69e0e"
    pub := "0000000297e9d9fa6f4926e3e1ecae02044e70bb855c86820bc8d62cf2d8fa997aa69e0e2dec0eab8dc64d1ee93d1fa7d5ef486c21e1582887ac2b85653c4a0743b92736"

    prvBytes, _ := hex.DecodeString(prv)
    pubBytes, _ := hex.DecodeString(pub)

    prikey := &xmss.PrivateKey{
        D: prvBytes,
    }
    pubkey := &xmss.PublicKey{
        X: pubBytes,
    }

    msg := "fgtgkijuijukokijdfrgtfv8juiju9ik"

    sig, err := Sign(prikey, []byte(msg))
    if err != nil {
        t.Fatal(err)
    }

    m := make([]byte, len(sig))

    if !Verify(pubkey, m, sig) {
        t.Error("XMSSMT Check failed. Verification does not match")
    }
}
