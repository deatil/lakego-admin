package ca

import (
    "testing"

    cryptobin_test "github.com/deatil/go-cryptobin/tool/test"
)

func Test_Check(t *testing.T) {
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    data := "ca data"

    assertNotEmpty(data, "Test_Check")
}
