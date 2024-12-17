package cipher

import (
    "testing"

    "github.com/deatil/go-cryptobin/tool/test"
)

func Test_GetCipher(t *testing.T) {
    assertNotEmpty := test.AssertNotEmptyT(t)
    assertError := test.AssertErrorT(t)

    res, err := GetCipher("Aes")

    assertError(err, "Test_GetCipher")
    assertNotEmpty(res, "Test_GetCipher")
}
