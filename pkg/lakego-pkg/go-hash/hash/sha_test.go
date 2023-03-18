package hash

import (
    "fmt"
    "testing"
)

var sha1Tests = []struct {
    input  string
    output string
}{
    {"sdfgsdgfsdfg123132", "70bad42c28d2cf0e4d3dc5f8f8c628616cee5dc1"},
    {"dfg.;kp[jewijr0-36lsd", "715ea0f7b5d09f660d21d765b4bb52e377f699c2"},
    {"123123", "601f1889667efaebb33b8c12572835da3f027f78"},
}

func Test_SHA1(t *testing.T) {
    assert := assertT(t)
    assertError := assertErrorT(t)

    for index, test := range sha1Tests {
        e := FromString(test.input).SHA1()

        t.Run(fmt.Sprintf("SHA1_test_%d", index), func(t *testing.T) {
            assertError(e.Error, "SHA1")
            assert(test.output, e.ToHexString(), "SHA1")
        })
    }
}

func Test_NewSHA1(t *testing.T) {
    assert := assertT(t)
    assertError := assertErrorT(t)

    for index, test := range sha1Tests {
        e := FromString("").NewSHA1().Write([]byte(test.input)).Sum(nil)

        t.Run(fmt.Sprintf("NewSHA1_test_%d", index), func(t *testing.T) {
            assertError(e.Error, "NewSHA1")
            assert(test.output, e.ToHexString(), "NewSHA1")
        })
    }
}
