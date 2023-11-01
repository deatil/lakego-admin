package sm2

import (
    "bytes"
    "testing"
    "crypto/rand"

    "github.com/tjfoc/gmsm/sm2"
)

func TestSM2ECDH(t *testing.T) {
    priv1, err := sm2.GenerateKey(rand.Reader)
    if err != nil {
        t.Fatal(err)
    }

    pub1 := &priv1.PublicKey

    // =======

    priv2, err := sm2.GenerateKey(rand.Reader)
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
func makeKey(pri *sm2.PrivateKey, pub *sm2.PublicKey) []byte {
    curve := sm2.P256Sm2()

    x, _ := curve.ScalarMult(pub.X, pub.Y, pri.D.Bytes())
    preMasterSecret := make([]byte, (curve.Params().BitSize+7)>>3)
    xBytes := x.Bytes()
    copy(preMasterSecret[len(preMasterSecret)-len(xBytes):], xBytes)

    return preMasterSecret
}
