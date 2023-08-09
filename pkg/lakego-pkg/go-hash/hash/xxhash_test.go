package hash

import (
    "fmt"
    "testing"
)

var xxhashTests = []struct {
    input  string
    output string
}{
    {"sdfgsdgfsdfg123132", "78d3b8dbb4db0f8d"},
    {"dfg.;kp[jewijr0-34lsd", "50998e31eb0519c3"},
    {"123123", "9a89a2de80ebd527"},
}

func Test_Xxhash(t *testing.T) {
    assert := assertT(t)
    assertError := assertErrorT(t)

    for index, test := range xxhashTests {
        e := FromString(test.input).Xxhash()

        t.Run(fmt.Sprintf("Xxhash_test_%d", index), func(t *testing.T) {
            assertError(e.Error, "Xxhash")
            assert(test.output, e.ToHexString(), "Xxhash")
        })
    }
}

func Test_NewXxhash(t *testing.T) {
    assert := assertT(t)
    assertError := assertErrorT(t)

    for index, test := range xxhashTests {
        e := FromString("").NewXxhash().Write([]byte(test.input)).Sum(nil)

        t.Run(fmt.Sprintf("NewXxhash_test_%d", index), func(t *testing.T) {
            assertError(e.Error, "NewXxhash")
            assert(test.output, e.ToHexString(), "NewXxhash")
        })
    }
}
