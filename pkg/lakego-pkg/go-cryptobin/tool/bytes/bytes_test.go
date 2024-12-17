package bytes

import (
    "testing"

    "github.com/deatil/go-cryptobin/tool/test"
)

func Test_SplitSize(t *testing.T) {
    assertEqual := test.AssertEqualT(t)

    data := SplitSize([]byte("1234567ytghyuj"), 5)
    check := [][]byte{
        []byte("12345"),
        []byte("67ytg"),
        []byte("hyuj"),
    }

    assertEqual(data, check, "Test_SplitSize")
}

func Test_FromString(t *testing.T) {
    assertEqual := test.AssertEqualT(t)

    data := FromString("1234567ytghyuj")
    check := []byte("1234567ytghyuj")

    assertEqual(data, check, "Test_FromString")
}

func Test_ToString(t *testing.T) {
    assertEqual := test.AssertEqualT(t)

    data := ToString([]byte("1234567ytghyuj"))
    check := "1234567ytghyuj"

    assertEqual(data, check, "Test_ToString")
}
