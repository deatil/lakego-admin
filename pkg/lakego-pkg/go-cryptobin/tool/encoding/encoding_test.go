package encoding

import (
    "fmt"
    "testing"

    "github.com/deatil/go-cryptobin/tool/test"
)

func Test_HexPadding(t *testing.T) {
    assertEqual := test.AssertEqualT(t)

    cases := []struct{
        src   string
        size  int
        check string
    } {
        {
            "",
            10,
            "0000000000",
        },
        {
            "asdfrt",
            10,
            "0000asdfrt",
        },
        {
            "asdfrt1234567",
            10,
            "frt1234567",
        },
        {
            "asdfrt1234",
            10,
            "asdfrt1234",
        },
    }

    for _, c := range cases {
        res := HexPadding(c.src, c.size)

        assertEqual(res, c.check, "Test_HexPadding")
    }
}

func Test_BytesPadding(t *testing.T) {
    assertEqual := test.AssertEqualT(t)

    cases := []struct{
        src   []byte
        size  int
        check []byte
    } {
        {
            []byte{},
            10,
            []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
        },
        {
            []byte("asdfrt"),
            10,
            append([]byte{0x00, 0x00, 0x00, 0x00}, []byte("asdfrt")...),
        },
        {
            []byte("asdfrt1234567"),
            10,
            []byte("frt1234567"),
        },
        {
            []byte("asdfrt1234"),
            10,
            []byte("asdfrt1234"),
        },
    }

    for i, c := range cases {
        res := BytesPadding(c.src, c.size)

        assertEqual(res, c.check, fmt.Sprintf("#%d: Test_BytesPadding", i))
    }
}
