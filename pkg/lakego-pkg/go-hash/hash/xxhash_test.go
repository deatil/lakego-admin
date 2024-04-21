package hash

import (
    "fmt"
    "testing"
)

var xxhashTests32 = []struct {
    input  string
    output string
}{
    {"sdfgsdgfsdfg123132", "ce45490c"},
    {"dfg.;kp[jewijr0-34lsd", "852a999c"},
    {"123123", "dbfd01d1"},
}

func Test_Xxhash32(t *testing.T) {
    assert := assertT(t)
    assertError := assertErrorT(t)

    for index, test := range xxhashTests32 {
        e := FromString(test.input).Xxhash32()

        t.Run(fmt.Sprintf("Xxhash32_test_%d", index), func(t *testing.T) {
            assertError(e.Error, "Xxhash32")
            assert(e.ToHexString(), test.output, "Xxhash32")
        })
    }
}

func Test_NewXxhash32(t *testing.T) {
    assert := assertT(t)
    assertError := assertErrorT(t)

    for index, test := range xxhashTests32 {
        e := FromString("").NewXxhash32().Write([]byte(test.input)).Sum(nil)

        t.Run(fmt.Sprintf("NewXxhash32_test_%d", index), func(t *testing.T) {
            assertError(e.Error, "NewXxhash32")
            assert(e.ToHexString(), test.output, "NewXxhash32")
        })
    }
}

// ========

var xxhashTests64 = []struct {
    input  string
    output string
}{
    {"sdfgsdgfsdfg123132", "78d3b8dbb4db0f8d"},
    {"dfg.;kp[jewijr0-34lsd", "50998e31eb0519c3"},
    {"123123", "9a89a2de80ebd527"},
}

func Test_Xxhash64(t *testing.T) {
    assert := assertT(t)
    assertError := assertErrorT(t)

    for index, test := range xxhashTests64 {
        e := FromString(test.input).Xxhash64()

        t.Run(fmt.Sprintf("Xxhash64_test_%d", index), func(t *testing.T) {
            assertError(e.Error, "Xxhash64")
            assert(e.ToHexString(), test.output, "Xxhash64")
        })
    }
}

func Test_NewXxhash64(t *testing.T) {
    assert := assertT(t)
    assertError := assertErrorT(t)

    for index, test := range xxhashTests64 {
        e := FromString("").NewXxhash64().Write([]byte(test.input)).Sum(nil)

        t.Run(fmt.Sprintf("NewXxhash64_test_%d", index), func(t *testing.T) {
            assertError(e.Error, "NewXxhash64")
            assert(e.ToHexString(), test.output, "NewXxhash64")
        })
    }
}
