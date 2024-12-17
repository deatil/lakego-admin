package pbes2

import (
    "testing"
    "crypto/rand"
    "encoding/asn1"

    cryptobin_test "github.com/deatil/go-cryptobin/tool/test"
)

func Test_EncryptPKCS8PrivateKey(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    data := "test-data"
    pass := "test-pass"

    block, err := EncryptPKCS8PrivateKey(rand.Reader, "ENCRYPTED PRIVATE KEY", []byte(data), []byte(pass))
    assertError(err, "EncryptPKCS8PrivateKey-EN")
    assertNotEmpty(block.Bytes, "EncryptPKCS8PrivateKey-EN")

    deData, err := DecryptPKCS8PrivateKey(block.Bytes, []byte(pass))
    assertError(err, "EncryptPKCS8PrivateKey-DE")
    assertNotEmpty(deData, "EncryptPKCS8PrivateKey-DE")

    assertEqual(string(deData), data, "EncryptPKCS8PrivateKey")
}

func Test_prfByOID_fail(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)

    oidFail := asn1.ObjectIdentifier{1, 222, 643, 777, 12, 13, 5, 1}

    _, err := prfByOID(oidFail)
    if err == nil {
        t.Error("should throw panic")
    }

    check := "go-cryptobin/pkcs8: unsupported hash (OID: 1.222.643.777.12.13.5.1)"
    assertEqual(err.Error(), check, "Test_prfByOID_fail")
}
