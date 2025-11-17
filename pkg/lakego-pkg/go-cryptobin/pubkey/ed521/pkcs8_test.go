package ed521

import (
    "testing"
    "crypto/rand"

    cryptobin_test "github.com/deatil/go-cryptobin/tool/test"
)

func Test_MarshalPKCS8(t *testing.T) {
    private, err := GenerateKey(rand.Reader)
    if err != nil {
        t.Fatal(err)
    }

    public := &private.PublicKey

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

    cryptobin_test.Equal(t, parsedPub, public)
    cryptobin_test.Equal(t, parsedPri, private)

    // t.Errorf("%s, %s \n", encodePEM(pubkey, "PUBLIC KEY"), encodePEM(prikey, "PRIVATE KEY"))
}

var privPEM = `-----BEGIN PRIVATE KEY-----
MFYCAQAwDgYKKwYBBAGC3CwCAQYABEFn+ELryWPBgSXqTFTDWjkuJWzLBl88Muvr
1+xy/LIGwSO2090Eo8LkEV57zYuG0Jjh81ZAuyNaqQ8tma1Wolq/JQ==
-----END PRIVATE KEY-----
`

var pubPEM = `-----BEGIN PUBLIC KEY-----
MIGZMA4GCisGAQQBgtwsAgEGAAOBhgAEAbouWIO8aWjrOjSCoHEXQ8u5BDir5nO6
qLhEJhyJSQWOjMrXrbANd3EMfFc9ZkCLG24qUEmFkhfu5fVGp0ZGAI5jAHuO05FQ
UBkXlDMB66rXFdayQ6TqtAkn4xPyJB38jF9pRfjNjjWW3hFQ20zYB9O00V/SwtEX
kfgAKH+ga7ps4WFd
-----END PUBLIC KEY-----
`

func Test_PKCS8_Check(t *testing.T) {
    test_PKCS8_Check(t, privPEM, pubPEM)
}

func test_PKCS8_Check(t *testing.T, priv, pub string) {
    assertEqual := cryptobin_test.AssertEqualT(t)

    parsedPub, err := ParsePublicKey(decodePEM(pub))
    if err != nil {
        t.Errorf("ParsePublicKey error: %s", err)
    }

    pubkey, err := MarshalPublicKey(parsedPub)
    if err != nil {
        t.Errorf("MarshalPublicKey error: %s", err)
    }

    pubPemCheck := encodePEM(pubkey, "PUBLIC KEY")
    assertEqual(pubPemCheck, pub, "test_Marshal_Check pubkey")

    // ===========

    parsedPriv, err := ParsePrivateKey(decodePEM(priv))
    if err != nil {
        t.Errorf("ParsePrivateKey error: %s", err)
    }

    privkey, err := MarshalPrivateKey(parsedPriv)
    if err != nil {
        t.Errorf("MarshalPrivateKey error: %s", err)
    }

    privPemCheck := encodePEM(privkey, "PRIVATE KEY")
    assertEqual(privPemCheck, priv, "test_Marshal_Check privkey")
}
