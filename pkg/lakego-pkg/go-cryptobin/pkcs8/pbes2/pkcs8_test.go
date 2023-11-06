package pbes2

import (
    "testing"
    "crypto/rand"

    cryptobin_test "github.com/deatil/go-cryptobin/tool/test"
)

func Test_EncryptPKCS8PrivateKey(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    data := "test-data"
    pass := "test-pass"

    block, err := EncryptPKCS8PrivateKey(rand.Reader, "RSA PUBLICKEY", []byte(data), []byte(pass))
    assertError(err, "EncryptPKCS8PrivateKey-EN")
    assertNotEmpty(block.Bytes, "EncryptPKCS8PrivateKey-EN")

    deData, err := DecryptPKCS8PrivateKey(block.Bytes, []byte(pass))
    assertError(err, "EncryptPKCS8PrivateKey-DE")
    assertNotEmpty(deData, "EncryptPKCS8PrivateKey-DE")

    assertEqual(string(deData), data, "EncryptPKCS8PrivateKey")
}
