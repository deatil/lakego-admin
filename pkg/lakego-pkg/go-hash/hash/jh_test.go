package hash

import (
    "fmt"
    "testing"
)

var jhTests = []struct {
    output string
    input  string
}{
    {"ce05383a3f918867994e9288d40adc5b735ff1a4f7a7f8cb9c50f0dc72328b66", "abcd"},
    {"40755d6a2482e7b66e0abbbcedb3ace7d22414e468c1390810ad991cd707aeff", "abcdabcdabcdab"},
    {"e9a0d9a0328df56e4d5634e825133e625892c582a2bb8dd8c963c37399083bd0", "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd"},
    {"3c4b76ca6be2d3c9d9e0af207557301cd9bbf9f478e1dee7f3303ad7eca24249", "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabc"},
    {"f083c34d561a5fff98a8ef1fbafb58ed5d1fe51e88545bacfcbf5b698da5206b", "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabc"},
}

func Test_JH(t *testing.T) {
    assert := assertT(t)
    assertError := assertErrorT(t)

    for index, test := range jhTests {
        e := FromString(test.input).JH()

        t.Run(fmt.Sprintf("JH %d", index), func(t *testing.T) {
            assertError(e.Error, "error")
            assert(e.ToHexString(), test.output, "to hex")
        })
    }
}

func Test_NewJH(t *testing.T) {
    assert := assertT(t)
    assertError := assertErrorT(t)

    for index, test := range jhTests {
        e := FromString("").NewJH().Write([]byte(test.input)).Sum(nil)

        t.Run(fmt.Sprintf("NewJH %d", index), func(t *testing.T) {
            assertError(e.Error, "error")
            assert(e.ToHexString(), test.output, "to hex")
        })
    }
}
