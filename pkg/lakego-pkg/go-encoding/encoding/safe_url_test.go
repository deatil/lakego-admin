package encoding

import (
    "fmt"
    "reflect"
    "testing"
)

func assertT(t *testing.T) func(any, any, string) {
    return func(actual any, expected any, msg string) {
        if !reflect.DeepEqual(actual, expected) {
            t.Errorf("Failed %s: actual: %v, expected: %v", msg, actual, expected)
        }
    }
}

func assertErrorT(t *testing.T) func(error, string) {
    return func(err error, msg string) {
        if err != nil {
            t.Errorf("Failed %s: error: %+v", msg, err)
        }
    }
}

var safeUrlTests = []struct {
    input  string
    output string
}{
    {"", ""},
    {"www.github.com?tab=star&open=lt", "www.github.com%3Ftab%3Dstar%26open%3Dlt"},
}

func TestSafeURL_From(t *testing.T) {
    assert := assertT(t)
    assertError := assertErrorT(t)

    for index, test := range safeUrlTests {
        e := FromString(test.output).SafeURLDecode()

        t.Run(fmt.Sprintf("test_%d", index), func(t *testing.T) {
            assertError(e.Error, "SafeURL_From")
            assert(test.input, e.ToString(), "SafeURL_From")
        })
    }
}

func TestSafeURL_To(t *testing.T) {
    assert := assertT(t)
    assertError := assertErrorT(t)

    for index, test := range safeUrlTests {
        e := FromString(test.input).SafeURLEncode()

        t.Run(fmt.Sprintf("test_%d", index), func(t *testing.T) {
            assertError(e.Error, "SafeURL_To")
            assert(test.output, e.ToString(), "SafeURL_To")
        })
    }
}
