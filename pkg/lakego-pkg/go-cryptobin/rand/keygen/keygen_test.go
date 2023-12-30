package keygen

import (
    "bytes"
    "testing"

    cryptobin_test "github.com/deatil/go-cryptobin/tool/test"
)

func Test_Gen(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    data := bytes.NewBufferString("dfgtryertdfgdr345343rtyedfgtryertdfgdr345343rtye")
    res, err := New(128, data).GenerateKey()

    check := []byte("dfgtryertdfgdr34")

    assertError(err, "Gen")
    assertNotEmpty(res, "Gen")

    assertEqual(string(res), string(check), "Gen")
}
