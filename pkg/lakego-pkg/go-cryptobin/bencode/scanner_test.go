package bencode

import (
    "bytes"
    "testing"

    cryptobin_test "github.com/deatil/go-cryptobin/tool/test"
)

func Test_scanner(t *testing.T) {
    eq := cryptobin_test.AssertEqualT(t)
    noErr := cryptobin_test.AssertNoErrorT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    d := bytes.NewBufferString("test data")

    s := scanner{
        r: d,
    }

    rb := make([]byte, 2)
    rbi, err := s.Read(rb)
    noErr(err, "Test_scanner-Read")
    eq(rbi, 2, "Test_scanner-Read-rbi")
    eq(string(rb), "te", "Test_scanner-Read")

    rbb, err := s.ReadByte()
    noErr(err, "Test_scanner-ReadByte")
    eq(string(rbb), "s", "Test_scanner-ReadByte")

    rbb2, err := s.ReadByte()
    noErr(err, "Test_scanner-ReadByte2")
    eq(string(rbb2), "t", "Test_scanner-ReadByte2")

    err = s.UnreadByte()
    noErr(err, "Test_scanner-UnreadByte")

    err = s.UnreadByte()
    assertError(err, "Test_scanner-UnreadByte2")

    rbb3, err := s.ReadByte()
    noErr(err, "Test_scanner-ReadByte3")
    eq(string(rbb3), "t", "Test_scanner-ReadByte3")
}
