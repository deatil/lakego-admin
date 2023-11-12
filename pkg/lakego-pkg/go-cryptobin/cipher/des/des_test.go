package des

import (
    "testing"

    cryptobin_test "github.com/deatil/go-cryptobin/tool/test"
)

func Test_Encrypt(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    key := "ujikioinsdujfic8"
    data := "ji9okind"

    dst := make([]byte, len(data))

    cip, err := NewTwoDESCipher([]byte(key))
    assertError(err, "Encrypt")

    cip.Encrypt(dst, []byte(data))
    assertNotEmpty(dst, "Encrypt-Encrypt")

    newData := make([]byte, len(dst))

    cip.Decrypt(newData, dst)
    assertNotEmpty(dst, "Encrypt-Decrypt")

    assertEqual(string(newData), data, "Encrypt")

}
