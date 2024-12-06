package deepcopy

import (
    "testing"
    "reflect"
)

func AssertEqualT(t *testing.T) func(any, any, string) {
    return func(actual any, expected any, msg string) {
        if !reflect.DeepEqual(actual, expected) {
            t.Errorf("Failed %s: actual: %v, expected: %v", msg, actual, expected)
        }
    }
}

type testPtr struct {
    B string
    C []byte
}

func Test_Check(t *testing.T) {
    assertEqual := AssertEqualT(t)

    {
        ptra := testPtr{
            B: "bbbbbbbbbbbb",
            C: []byte("cccccccccc"),
        }
        ptrb := Copy(ptra)

        assertEqual(ptrb, ptra, "Test_Check-Ptr")
    }

    {
        ptra := []byte("cccccccccc")
        ptrb := Copy(ptra)

        assertEqual(ptrb, ptra, "Test_Check-Slice")
    }

    {
        ptra := map[string]any{
            "a": "aaaaaaaa",
            "cc": "cccccccccc",
            "ddd": 111111,
        }
        ptrb := Copy(ptra)

        assertEqual(ptrb, ptra, "Test_Check-map")
    }

    {
        var ptra any = "ttttttttttt"
        ptrb := Copy(ptra)

        assertEqual(ptrb, ptra, "Test_Check-map")
    }
}
