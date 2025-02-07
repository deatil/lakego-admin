package cipher

import (
    "testing"

    "github.com/deatil/go-cryptobin/tool/test"
)

func Test_GetCipher(t *testing.T) {
    assertNotEmpty := test.AssertNotEmptyT(t)
    assertNoError := test.AssertNoErrorT(t)

    res, err := GetCipher("Aes")

    assertNoError(err, "Test_GetCipher")
    assertNotEmpty(res, "Test_GetCipher")
}
