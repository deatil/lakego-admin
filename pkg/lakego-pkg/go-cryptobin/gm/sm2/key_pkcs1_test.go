package sm2

import (
    "bytes"
    "testing"
    "crypto/rand"

    cryptobin_test "github.com/deatil/go-cryptobin/tool/test"
)

func TestSM2ECDH(t *testing.T) {
    priv1, err := GenerateKey(rand.Reader)
    if err != nil {
        t.Fatal(err)
    }

    pub1 := &priv1.PublicKey

    // =======

    priv2, err := GenerateKey(rand.Reader)
    if err != nil {
        t.Fatal(err)
    }

    pub2 := &priv2.PublicKey

    // =======

    secret1 := makeKey(priv1, pub2)
    if secret1 == nil {
        t.Errorf("expected ECDH1 nil")
    }

    // =======

    secret2 := makeKey(priv2, pub1)
    if secret2 == nil {
        t.Errorf("expected ECDH2 nil")
    }

    // =======

    if !bytes.Equal(secret1, secret2) {
        t.Error("two ECDH computations came out different")
    }
}

// ECDH 生成密钥
func makeKey(pri *PrivateKey, pub *PublicKey) []byte {
    curve := P256()

    x, _ := curve.ScalarMult(pub.X, pub.Y, pri.D.Bytes())
    preMasterSecret := make([]byte, (curve.Params().BitSize+7)>>3)
    xBytes := x.Bytes()
    copy(preMasterSecret[len(preMasterSecret)-len(xBytes):], xBytes)

    return preMasterSecret
}

func Test_PKCS1(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)

    priv1, err := GenerateKey(rand.Reader)
    if err != nil {
        t.Fatal(err)
    }

    pem1, err := MarshalSM2PrivateKey(priv1)
    if err != nil {
        t.Fatal(err)
    }

    if len(pem1) == 0 {
        t.Error("priv pem make error")
    }

    priv2, err := ParseSM2PrivateKey(pem1)
    if err != nil {
        t.Fatal(err)
    }

    assertEqual(priv2, priv1, "PKCS1")
}
