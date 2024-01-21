package sm2

import (
    "testing"
    "crypto/rand"
    "encoding/pem"

    cryptobin_test "github.com/deatil/go-cryptobin/tool/test"
)

func Test_PKCS8(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)

    priv1, err := GenerateKey(rand.Reader)
    if err != nil {
        t.Fatal(err)
    }

    pem1, err := MarshalPrivateKey(priv1)
    if err != nil {
        t.Fatal(err)
    }

    if len(pem1) == 0 {
        t.Error("priv pem make error")
    }

    priv2, err := ParsePrivateKey(pem1)
    if err != nil {
        t.Fatal(err)
    }

    assertEqual(priv2, priv1, "PKCS8")
}

func Test_PublicKey(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)

    priv1, err := GenerateKey(rand.Reader)
    if err != nil {
        t.Fatal(err)
    }
    pub1 := &priv1.PublicKey

    pem1, err := MarshalPublicKey(pub1)
    if err != nil {
        t.Fatal(err)
    }

    if len(pem1) == 0 {
        t.Error("pub pem make error")
    }

    pub2, err := ParsePublicKey(pem1)
    if err != nil {
        t.Fatal(err)
    }

    assertEqual(pub2, pub1, "PublicKey")
}

var testPrivateKey = `
-----BEGIN PRIVATE KEY-----
MIGIAgEAMBQGCCqBHM9VAYItBggqgRzPVQGCLQRtMGsCAQEEIIfYbABfRJN5ZBkW
teXxzV0hzNrWBhN0Fmn0cJRqy50XoUQDQgAEbyM/EfFVSXAdxeZ3ovXSAtG3GD1v
av+xanZVivqzzKU35ILFbXef9YkxHQOpQRRifIj99nJS7SH+cFH5S0jKLw==
-----END PRIVATE KEY-----
`

func Test_PKCS8_Check(t *testing.T) {
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    keyData := []byte(testPrivateKey)
    block, _ := pem.Decode(keyData)

    priv, err := ParsePrivateKey(block.Bytes)
    if err != nil {
        t.Fatal(err)
    }

    assertNotEmpty(priv, "PKCS8_Check")
}
