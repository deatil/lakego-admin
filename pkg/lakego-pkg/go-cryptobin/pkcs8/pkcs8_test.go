package pkcs8

import (
    "testing"
    "crypto/rand"

    cryptobin_test "github.com/deatil/go-cryptobin/tool/test"
)

func Test_EncryptPEMBlock(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    data := "test-data"
    pass := "test-pass"

    block, err := EncryptPEMBlock(rand.Reader, "ENCRYPTED PRIVATE KEY", []byte(data), []byte(pass), DefaultOpts)
    assertError(err, "EncryptPEMBlock-EN")
    assertNotEmpty(block.Bytes, "EncryptPEMBlock-EN")

    deData, err := DecryptPEMBlock(block, []byte(pass))
    assertError(err, "EncryptPEMBlock-DE")
    assertNotEmpty(deData, "EncryptPEMBlock-DE")

    assertEqual(string(deData), data, "EncryptPEMBlock")
}
