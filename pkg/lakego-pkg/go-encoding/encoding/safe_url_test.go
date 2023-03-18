package encoding

import (
    "fmt"
    "testing"
)

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
