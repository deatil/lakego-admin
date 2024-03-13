package puny

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
        decoded: "∏∪∩",
        encoded: "q9g0cc",
    },
    {
        decoded: "Hello!!",
        encoded: "Hello!!-",
    },
    {
        decoded: "puny Encoding，？：+【‘；’",
        encoded: "puny Encoding+-yb3hqa1950e6u24cvhaxa3f",
    },
    {
        decoded: "测试!",
        encoded: "!-rq9bs28f",
    },
    {
        decoded: "ǐǒó チツチノハフヘキキξεζοреё┢┣┮┐┑ 《《‖∶",
        encoded: "  -4ja79fka410aha6dl49ipd3io866avhg1plqa10asa3sp25sa586aa29ba1fto2a8opd",
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
