package sm2

import (
    "fmt"
    "strings"
    "testing"
    "crypto/rand"
    "encoding/pem"
    "encoding/hex"

    cryptobin_test "github.com/deatil/go-cryptobin/tool/test"
)

func decodePEM(src string) []byte {
    block, _ := pem.Decode([]byte(src))
    if block == nil {
        panic("failed to parse PEM block containing the key")
    }

    return block.Bytes
}

func encodePEM(src []byte, typ string) string {
    keyBlock := &pem.Block{
        Type:  typ,
        Bytes: src,
    }

    keyData := pem.EncodeToMemory(keyBlock)

    return string(keyData)
}

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

var testPublicKey = `
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEW6gm/jIEusEuBZHnu/Yr5vN96pnh
5NpeowHwvqpzXyzaTr/9Tb6A9M2RGkdSDYP7H6x8AI697Ea54u3opJqGMQ==
-----END PUBLIC KEY-----
`
var testPublicKeyBytes = `035ba826fe3204bac12e0591e7bbf62be6f37dea99e1e4da5ea301f0beaa735f2c`

func Test_Compress(t *testing.T) {
    pub := decodePEM(testPublicKey)

    pubkey, err := ParsePublicKey(pub)
    if err != nil {
        t.Fatal(err)
    }

    comkey := Compress(pubkey)

    check := testPublicKeyBytes
    got := fmt.Sprintf("%x", comkey)

    if got != check {
        t.Errorf("Compress error, got %s, want %s", got, check)
    }
}

func Test_Decompress(t *testing.T) {
    pub, err := hex.DecodeString(testPublicKeyBytes)
    if err != nil {
        t.Fatal(err)
    }

    pubkey, err := Decompress(pub)
    if err != nil {
        t.Fatal(err)
    }

    pubkeyBytes, err := MarshalPublicKey(pubkey)
    if err != nil {
        t.Fatal(err)
    }

    check := testPublicKey
    got := encodePEM(pubkeyBytes, "PUBLIC KEY")

    if strings.TrimSpace(got) != strings.TrimSpace(check) {
        t.Errorf("Decompress error, got %s, want %s", got, check)
    }
}
