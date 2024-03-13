package quotedprintable

import (
    "testing"
)

type testPair struct {
    decoded string
    encoded string
}

type malformedTestPair struct {
    encoded string
    error error
}

var pairs = []testPair{
    {
        decoded: `AB== fr gt\tdf`,
        encoded: "AB=3D=3D fr gt\\tdf",
    },
    {
        decoded: "Hello!! gt\tdf",
        encoded: "Hello!! gt\tdf",
    },
    {
        decoded: `quoted\nprin\rtabl e gt\tdf`,
        encoded: "quoted\\nprin\\rtabl e gt\\tdf",
    },
    {
        decoded: `ietf!\rjj`,
        encoded: "ietf!\\rjj",
    },
    {
        decoded: `test tyu\nikl dolor sit ametf5.h`,
        encoded: "test tyu\\nikl dolor sit ametf5.h",
    },
}

func testEqual(t *testing.T, msg string, args ...any) bool {
    if args[len(args)-2] != args[len(args)-1] {
        t.Errorf(msg, args...)
        return false
    }

    return true
}

func TestEncode(t *testing.T) {
    for _, p := range pairs {
        got, err := StdEncoding.EncodeToString([]byte(p.decoded))
        if err != nil {
            t.Fatal(err)
        }

        testEqual(t, "Encode(%q) = %q, want %q", p.decoded, got, p.encoded)
    }
}

func TestDecode(t *testing.T) {
    for _, p := range pairs {
        got, err := StdEncoding.DecodeString(p.encoded)
        if err != nil {
            t.Fatal(err)
        }

        testEqual(t, "Decode(%q) = %q, want %q", p.encoded, string(got), p.decoded)
    }
}
