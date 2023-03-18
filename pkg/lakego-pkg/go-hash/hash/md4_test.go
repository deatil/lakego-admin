package hash

import (
    "fmt"
    "testing"
)

var md4Tests = []struct {
    input  string
    output string
}{
    {"sdfgsdgfsdfg123132", "6446daa2729ca846dcd524ce7dabbaa2"},
    {"dfg.;kp[jewijr0-34lsd", "2731537e39ad34cd0dd49997966f0660"},
    {"123123", "4a4a963e47c7b8a3b355e0e0c90d0aa0"},
}

func Test_MD4(t *testing.T) {
    assert := assertT(t)
    assertError := assertErrorT(t)

    for index, test := range md4Tests {
        e := FromString(test.input).MD4()

        t.Run(fmt.Sprintf("md5_test_%d", index), func(t *testing.T) {
            assertError(e.Error, "MD4")
            assert(test.output, e.ToHexString(), "MD4")
        })
    }
}

func Test_NewMD4(t *testing.T) {
    assert := assertT(t)
    assertError := assertErrorT(t)

    for index, test := range md4Tests {
        e := FromString("").NewMD4().Write([]byte(test.input)).Sum(nil)

        t.Run(fmt.Sprintf("NewMD4_test_%d", index), func(t *testing.T) {
            assertError(e.Error, "NewMD4")
            assert(test.output, e.ToHexString(), "NewMD4")
        })
    }
}
