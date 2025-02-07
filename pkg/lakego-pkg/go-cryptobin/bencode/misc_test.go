package bencode

import (
    "testing"

    cryptobin_test "github.com/deatil/go-cryptobin/tool/test"
)

func Test_bytesAsString(t *testing.T) {
    eq := cryptobin_test.AssertEqualT(t)

    d := []byte("test-data")

    eq(bytesAsString(d), "test-data", "Test_bytesAsString")
}

func Test_splitPieceHashes(t *testing.T) {
    eq := cryptobin_test.AssertEqualT(t)
    noErr := cryptobin_test.AssertNoErrorT(t)

    d := "test--data1234567890data..test0987654321"
    res, err := splitPieceHashes(d)
    noErr(err, "Test_splitPieceHashes")

    check := [][20]byte{
        [20]byte([]byte("test--data1234567890")),
        [20]byte([]byte("data..test0987654321")),
    }
    eq(res, check, "Test_bytesAsString")
}
