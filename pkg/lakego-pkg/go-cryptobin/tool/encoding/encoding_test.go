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
        {
            res := HexPadding(c.src, c.size)

            assertEqual(res, c.check, "Test_HexPadding")
        }
        {
            res := New().HexPadding(c.src, c.size)

            assertEqual(res, c.check, "Test_HexPadding")
        }
        {
            res := StdEncoding.HexPadding(c.src, c.size)

            assertEqual(res, c.check, "Test_HexPadding")
        }
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
        {
            res := BytesPadding(c.src, c.size)

            assertEqual(res, c.check, fmt.Sprintf("#%d: Test_BytesPadding", i))
        }
        {
            res := New().BytesPadding(c.src, c.size)

            assertEqual(res, c.check, fmt.Sprintf("#%d: Test_BytesPadding", i))
        }
        {
            res := StdEncoding.BytesPadding(c.src, c.size)

            assertEqual(res, c.check, fmt.Sprintf("#%d: Test_BytesPadding", i))
        }
    }
}

func Test_Base32Encode(t *testing.T) {
    for _, p := range base32Pairs {
        got := Base32Encode([]byte(p.decoded))
        test.Equalf(t, p.encoded, got, "Base32Encode(%q) = %q, want %q", p.decoded, got, p.encoded)
    }
}

func Test_Base32Decode(t *testing.T) {
    for _, p := range base32Pairs {
        got, err := Base32Decode(p.encoded)

        test.NoErrorf(t, err, "Base32Decode(%q) = error %v, want %v", p.encoded, err, error(nil))
        test.Equalf(t, p.decoded, string(got), "Base32Decode(%q) = %q, want %q", p.encoded, string(got), p.decoded)
    }
}

func Test_Base64Encode(t *testing.T) {
    for _, p := range base64Pairs {
        got := Base64Encode([]byte(p.decoded))
        test.Equalf(t, p.encoded, got, "Base64Encode(%q) = %q, want %q", p.decoded, got, p.encoded)
    }
}

func Test_Base64Decode(t *testing.T) {
    for _, p := range base64Pairs {
        got, err := Base64Decode(p.encoded)

        test.NoErrorf(t, err, "Base64Decode(%q) = error %v, want %v", p.encoded, err, error(nil))
        test.Equalf(t, p.decoded, string(got), "Base64Decode(%q) = %q, want %q", p.encoded, string(got), p.decoded)
    }
}

func Test_HexEncode(t *testing.T) {
    for _, p := range hexEncDecTests {
        got := HexEncode(p.dec)
        test.Equalf(t, p.enc, got, "HexEncode(%q) = %q, want %q", p.dec, got, p.enc)
    }
}

func Test_HexDecode(t *testing.T) {
    for _, p := range hexEncDecTests {
        got, err := HexDecode(p.enc)

        test.NoErrorf(t, err, "HexDecode(%q) = error %v, want %v", p.enc, err, error(nil))
        test.Equalf(t, p.dec, got, "HexDecode(%q) = %q, want %q", p.enc, got, p.dec)
    }
}

type testpair struct {
    decoded, encoded string
}

var base32Pairs = []testpair{
    // RFC 4648 examples
    {"", ""},
    {"f", "MY======"},
    {"fo", "MZXQ===="},
    {"foo", "MZXW6==="},
    {"foob", "MZXW6YQ="},
    {"fooba", "MZXW6YTB"},
    {"foobar", "MZXW6YTBOI======"},

    // Wikipedia examples, converted to base32
    {"sure.", "ON2XEZJO"},
    {"sure", "ON2XEZI="},
    {"sur", "ON2XE==="},
    {"su", "ON2Q===="},
    {"leasure.", "NRSWC43VOJSS4==="},
    {"easure.", "MVQXG5LSMUXA===="},
    {"asure.", "MFZXK4TFFY======"},
    {"sure.", "ON2XEZJO"},

    // bigtest
    {
        "Twas brillig, and the slithy toves",
        "KR3WC4ZAMJZGS3DMNFTSYIDBNZSCA5DIMUQHG3DJORUHSIDUN53GK4Y=",
    },
}

var base64Pairs = []testpair{
    // RFC 3548 examples
    {"\x14\xfb\x9c\x03\xd9\x7e", "FPucA9l+"},
    {"\x14\xfb\x9c\x03\xd9", "FPucA9k="},
    {"\x14\xfb\x9c\x03", "FPucAw=="},

    // RFC 4648 examples
    {"", ""},
    {"f", "Zg=="},
    {"fo", "Zm8="},
    {"foo", "Zm9v"},
    {"foob", "Zm9vYg=="},
    {"fooba", "Zm9vYmE="},
    {"foobar", "Zm9vYmFy"},

    // Wikipedia examples
    {"sure.", "c3VyZS4="},
    {"sure", "c3VyZQ=="},
    {"sur", "c3Vy"},
    {"su", "c3U="},
    {"leasure.", "bGVhc3VyZS4="},
    {"easure.", "ZWFzdXJlLg=="},
    {"asure.", "YXN1cmUu"},
    {"sure.", "c3VyZS4="},

    // bigtest
    {
        "Twas brillig, and the slithy toves",
        "VHdhcyBicmlsbGlnLCBhbmQgdGhlIHNsaXRoeSB0b3Zlcw==",
    },
}

type encDecTest struct {
    enc string
    dec []byte
}

var hexEncDecTests = []encDecTest{
    {"", []byte{}},
    {"0001020304050607", []byte{0, 1, 2, 3, 4, 5, 6, 7}},
    {"08090a0b0c0d0e0f", []byte{8, 9, 10, 11, 12, 13, 14, 15}},
    {"f0f1f2f3f4f5f6f7", []byte{0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7}},
    {"f8f9fafbfcfdfeff", []byte{0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff}},
    {"67", []byte{'g'}},
    {"e3a1", []byte{0xe3, 0xa1}},
}
