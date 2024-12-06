package utils

import (
    "testing"

    "github.com/deatil/go-cryptobin/tool/test"
)

func Test_GenRandom(t *testing.T) {
    assertEqual := test.AssertEqualT(t)
    assertNotEmpty := test.AssertNotEmptyT(t)

    data, _ := GenRandom(12)
    assertNotEmpty(data, "Test_GenRandom")

    assertEqual(len(data), 12, "Test_GenRandom")
}
