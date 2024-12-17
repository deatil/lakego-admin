package ecsdsa

import (
    "testing"
    "crypto/rand"
    "crypto/elliptic"

    cryptobin_test "github.com/deatil/go-cryptobin/tool/test"
)

func Test_MarshalPKCS1(t *testing.T) {
    private, err := GenerateKey(rand.Reader, elliptic.P224())
    if err != nil {
        t.Fatal(err)
    }

    prikey, err := MarshalECPrivateKey(private)
    if err != nil {
        t.Errorf("MarshalECPrivateKey error: %s", err)
    }

    parsedPri, err := ParseECPrivateKey(prikey)
    if err != nil {
        t.Errorf("ParseECPrivateKey error: %s", err)
    }

    if !private.Equal(parsedPri) {
        t.Errorf("parsedPri error")
    }

    // t.Errorf("%s \n", encodePEM(prikey, "EC PRIVATE KEY"))
}

func Test_MarshalPKCS8(t *testing.T) {
    private, err := GenerateKey(rand.Reader, elliptic.P224())
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

    if !public.Equal(parsedPub) {
        t.Errorf("parsedPub error")
    }
    if !private.Equal(parsedPri) {
        t.Errorf("parsedPri error")
    }

    // t.Errorf("%s, %s \n", encodePEM(pubkey, "PUBLIC KEY"), encodePEM(prikey, "PRIVATE KEY"))
}

var privPEM = `-----BEGIN PRIVATE KEY-----
MHcCAQAwDwYGKPQoAwALBgUrgQQAIQRhMF8CAQEEHHNki0HgNBV6AP+lVTF75L/6
kI+TKkdd0Sr0J7uhPAM6AAT2bjrDo+YFXwoLl9VPJVUaPdtjiLyhXiffk2Zd6I50
aYCkvUyULzB1CbU+lkrxddAAT5yUn0lQcw==
-----END PRIVATE KEY-----
`

var pubPEM = `-----BEGIN PUBLIC KEY-----
ME0wDwYGKPQoAwALBgUrgQQAIQM6AAT2bjrDo+YFXwoLl9VPJVUaPdtjiLyhXiff
k2Zd6I50aYCkvUyULzB1CbU+lkrxddAAT5yUn0lQcw==
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

var privPKCS1PEM = `-----BEGIN EC PRIVATE KEY-----
MGgCAQEEHGkD79SVxSRQWhWoyRUglQ6OakxZr8TLqH+giZSgBwYFK4EEACGhPAM6
AAQfRdU3F5z4R0hKEZ1Zd2a3nOm5Ws0v96q1UX4DBgvVHXO7MjmS9Qz/UKXC9GpJ
2khyCo4j/LLArg==
-----END EC PRIVATE KEY-----
`

func Test_PKCS1_Check(t *testing.T) {
    test_PKCS1_Check(t, privPKCS1PEM)
}

func test_PKCS1_Check(t *testing.T, priv string) {
    assertEqual := cryptobin_test.AssertEqualT(t)

    parsedPriv, err := ParseECPrivateKey(decodePEM(priv))
    if err != nil {
        t.Errorf("ParseECPrivateKey error: %s", err)
    }

    privkey, err := MarshalECPrivateKey(parsedPriv)
    if err != nil {
        t.Errorf("MarshalECPrivateKey error: %s", err)
    }

    privPemCheck := encodePEM(privkey, "EC PRIVATE KEY")
    assertEqual(privPemCheck, priv, "test_Marshal_Check privkey")
}
