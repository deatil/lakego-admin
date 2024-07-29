package goch

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

func Test_ToJSON(t *testing.T) {
    eq := AssertEqualT(t)

    test := map[string]any{
        "test1": "value1",
        "test5": "value5",
    }

    res := ToJSON(test)
    check := `{"test1":"value1","test5":"value5"}`

    eq(string(res), check, "Test_ToJSON")
}

func Test_ToString(t *testing.T) {
    eq := AssertEqualT(t)

    test := []byte("test1")

    res := ToString(test)
    check := `test1`

    eq(string(res), check, "Test_ToString")
}
