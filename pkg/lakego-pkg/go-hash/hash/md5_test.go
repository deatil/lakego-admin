package hash

import (
    "fmt"
    "testing"
)

var md5Tests = []struct {
    input  string
    output string
}{
    {"sdfgsdgfsdfg123132", "f7d9f5d96d7935a47cee64ab0560843d"},
    {"dfg.;kp[jewijr0-34lsd", "808c4183cd07a8f9fdac2dc06107d0d9"},
    {"123123", "4297f44b13955235245b2497399d7a93"},
}

func Test_MD5(t *testing.T) {
    assert := assertT(t)
    assertError := assertErrorT(t)

    for index, test := range md5Tests {
        e := FromString(test.input).MD5()

        t.Run(fmt.Sprintf("md5_test_%d", index), func(t *testing.T) {
            assertError(e.Error, "MD5")
            assert(test.output, e.ToHexString(), "MD5")
        })
    }
}

func Test_NewMD5(t *testing.T) {
    assert := assertT(t)
    assertError := assertErrorT(t)

    for index, test := range md5Tests {
        e := FromString("").NewMD5().Write([]byte(test.input)).Sum(nil)

        t.Run(fmt.Sprintf("NewMD5_test_%d", index), func(t *testing.T) {
            assertError(e.Error, "NewMD5")
            assert(test.output, e.ToHexString(), "NewMD5")
        })
    }
}
