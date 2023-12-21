package ed448

import (
    "testing"
    "crypto/rand"
    "encoding/pem"

    cryptobin_test "github.com/deatil/go-cryptobin/tool/test"
)

func decodePEM(pubPEM string) []byte {
    block, _ := pem.Decode([]byte(pubPEM))
    if block == nil {
        panic("failed to parse PEM block containing the key")
    }

    return block.Bytes
}

func Test_Marshal(t *testing.T) {
    public, private, _ := GenerateKey(rand.Reader)

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
}

var testPkcs8PriKey = `
-----BEGIN PRIVATE KEY-----
MEcCAQAwBQYDK2VxBDsEOWyCpWLLgI0Q1jK+ichRPr9skp803fqMn2PJlg7240ij
UoyKP8wvBE45o/xblEkvjwMudUmiAJj5Ww==
-----END PRIVATE KEY-----
`

var testPkcs8PubKey = `
-----BEGIN PUBLIC KEY-----
MEMwBQYDK2VxAzoAX9dEm1m0Yf0s54fsYWrUah2hNCSFpw4fig6nXYDpZ3jt8SR2
m0bHBhvWeD3x5Q9s0foavq/oJWGA
-----END PUBLIC KEY-----
`

func Test_Marshal_Check(t *testing.T) {
    assertError := cryptobin_test.AssertErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    pubkey := decodePEM(testPkcs8PubKey)
    parsedPub, err := ParsePublicKey(pubkey)

    assertError(err, "ParsePublicKey")
    assertNotEmpty(parsedPub, "ParsePublicKey")

    prikey := decodePEM(testPkcs8PriKey)
    parsedPri, err := ParsePrivateKey(prikey)

    assertError(err, "ParsePrivateKey")
    assertNotEmpty(parsedPri, "ParsePrivateKey")
}

func Test_Sign_Check(t *testing.T) {
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)
    assertBool := cryptobin_test.AssertBoolT(t)

    pubkey := decodePEM(testPkcs8PubKey)
    parsedPub, _ := ParsePublicKey(pubkey)

    prikey := decodePEM(testPkcs8PriKey)
    parsedPri, _ := ParsePrivateKey(prikey)

    message := []byte("test-passstest-passstest-passs")

    sig := Sign(parsedPri, message)
    assertNotEmpty(sig, "Sign")

    v := Verify(parsedPub, message, sig)
    assertBool(v, "Sign")
}
