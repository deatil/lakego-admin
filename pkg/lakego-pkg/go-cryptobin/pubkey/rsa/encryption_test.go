package rsa

import (
    "testing"
    "crypto/rand"

    cryptobin_test "github.com/deatil/go-cryptobin/tool/test"
)

func Test_PublicKeyBytes_Encrypt(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertNoError := cryptobin_test.AssertNoErrorT(t)

    testPub := []byte(testPublicKeyCheck)
    pub, err := ParseXMLPublicKey(testPub)

    assertNoError(err, "Test_PublicKeyBytes_Encrypt-pub-Error")

    testPri := []byte(testPrivateKeyCheck)
    pri, err := ParseXMLPrivateKey(testPri)

    assertNoError(err, "Test_PublicKeyBytes_Encrypt-pri-Error")

    msg := make([]byte, 128)
    rand.Read(msg)

    ct, err := PublicKeyBytes(pub, msg, true)
    assertNoError(err, "Test_PublicKeyBytes_Encrypt-en-Error")

    res, err := PrivateKeyBytes(pri, ct, false)
    assertNoError(err, "Test_PublicKeyBytes_Encrypt-de-Error")

    assertEqual(string(res), string(msg), "Test_PublicKeyBytes_Encrypt")
}

func Test_PrivateKeyBytes_Encrypt(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertNoError := cryptobin_test.AssertNoErrorT(t)

    testPub := []byte(testPublicKeyCheck)
    pub, err := ParseXMLPublicKey(testPub)

    assertNoError(err, "Test_PrivateKeyBytes_Encrypt-pub-Error")

    testPri := []byte(testPrivateKeyCheck)
    pri, err := ParseXMLPrivateKey(testPri)

    assertNoError(err, "Test_PrivateKeyBytes_Encrypt-pri-Error")

    msg := make([]byte, 128)
    rand.Read(msg)

    ct, err := PrivateKeyBytes(pri, msg, true)
    assertNoError(err, "Test_PrivateKeyBytes_Encrypt-en-Error")

    res, err := PublicKeyBytes(pub, ct, false)
    assertNoError(err, "Test_PrivateKeyBytes_Encrypt-de-Error")

    assertEqual(string(res), string(msg), "Test_PrivateKeyBytes_Encrypt")
}
