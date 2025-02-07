package pkcs

import (
    "io"
    "testing"
    "crypto/rand"

    pkcs_pbes1 "github.com/deatil/go-cryptobin/pkcs/pbes1"
    pkcs_pbes2 "github.com/deatil/go-cryptobin/pkcs/pbes2"
    cryptobin_test "github.com/deatil/go-cryptobin/tool/test"
)

type testCbcParams []byte

func Test_AES256CBC(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertNoError := cryptobin_test.AssertNoErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    pass := make([]byte, 32)
    if _, err := io.ReadFull(rand.Reader, pass); err != nil {
        t.Error(err.Error())
    }

    data := []byte("1awersdf")

    c := NewSym[testCbcParams](pkcs_pbes2.AES256CBC)

    endata, parm, err := c.Encrypt(rand.Reader, pass, data)
    assertNoError(err, "En")
    assertNotEmpty(endata, "En")

    dedata, err := c.Decrypt(pass, parm, endata)
    assertNoError(err, "En-de")
    assertNotEmpty(dedata, "En-de")

    assertEqual(dedata, data, "En")
}

type testPbeCBCParams struct {
    Salt           []byte
    IterationCount int
}

func Test_MD5AndDES(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertNoError := cryptobin_test.AssertNoErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    pass := make([]byte, 8)
    if _, err := io.ReadFull(rand.Reader, pass); err != nil {
        t.Error(err.Error())
    }

    data := []byte("1awersdf")

    c := NewSym[testPbeCBCParams](pkcs_pbes1.MD5AndDES)

    endata, parm, err := c.Encrypt(rand.Reader, pass, data)
    assertNoError(err, "En")
    assertNotEmpty(endata, "En")

    dedata, err := c.Decrypt(pass, parm, endata)
    assertNoError(err, "En-de")
    assertNotEmpty(dedata, "En-de")

    assertEqual(dedata, data, "En")
}
