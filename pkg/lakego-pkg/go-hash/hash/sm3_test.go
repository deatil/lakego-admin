package hash

import (
    "fmt"
    "testing"
)

var sm3Tests = []struct {
    output string
    input  string
}{
    {"90d52a2e85631a8d6035262626941fa11b85ce570cec1e3e991e2dd7ed258148", "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd"},
    {"e1c53f367a9c5d19ab6ddd30248a7dafcc607e74e6bcfa52b00e0ba35e470421", "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabc"},
    {"520472cafdaf21d994c5849492ba802459472b5206503389fc81ff73adbec1b4", "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabc"},
}

func Test_SM3(t *testing.T) {
    assert := assertT(t)
    assertError := assertErrorT(t)

    for index, test := range sm3Tests {
        e := FromString(test.input).SM3()

        t.Run(fmt.Sprintf("SM3 %d", index), func(t *testing.T) {
            assertError(e.Error, "SM3")
            assert(test.output, e.ToHexString(), "SM3")
        })
    }
}

func Test_NewSM3(t *testing.T) {
    assert := assertT(t)
    assertError := assertErrorT(t)

    for index, test := range sm3Tests {
        e := FromString("").NewSM3().Write([]byte(test.input)).Sum(nil)

        t.Run(fmt.Sprintf("NewSM3 %d", index), func(t *testing.T) {
            assertError(e.Error, "NewSM3")
            assert(test.output, e.ToHexString(), "NewSM3")
        })
    }
}
