package bencode

import (
    "testing"

    cryptobin_test "github.com/deatil/go-cryptobin/tool/test"
)

func Test_Bytes(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    data := []byte("123123")

    var buf Bytes
    err := buf.UnmarshalBencode(data)

    assertError(err, "Bytes-UnmarshalBencode")

    res, err := buf.MarshalBencode()

    assertError(err, "Bytes-MarshalBencode")
    assertEqual(res, data, "Bytes-MarshalBencode")

    res2 := buf.GoString()

    assertEqual(res2, "bencode.Bytes(\"123123\")", "Bytes-GoString")
}
