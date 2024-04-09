package hash

import (
    "fmt"
    "testing"
)

var blake256Tests = []struct {
    output string
    input  string
}{
    {"7576698ee9cad30173080678e5965916adbb11cb5245d386bf1ffda1cb26c9d7",
        "The quick brown fox jumps over the lazy dog"},
    {"07663e00cf96fbc136cf7b1ee099c95346ba3920893d18cc8851f22ee2e36aa6",
        "BLAKE"},
}

func Test_Blake256(t *testing.T) {
    assert := assertT(t)
    assertError := assertErrorT(t)

    for index, test := range blake256Tests {
        e := FromString(test.input).Blake256()

        t.Run(fmt.Sprintf("Blake256_test_%d", index), func(t *testing.T) {
            assertError(e.Error, "Blake256")
            assert(test.output, e.ToHexString(), "Blake256")
        })
    }
}

func Test_NewBlake256(t *testing.T) {
    assert := assertT(t)
    assertError := assertErrorT(t)

    for index, test := range blake256Tests {
        e := FromString("").NewBlake256().Write([]byte(test.input)).Sum(nil)

        t.Run(fmt.Sprintf("NewBlake256_test_%d", index), func(t *testing.T) {
            assertError(e.Error, "NewBlake256")
            assert(test.output, e.ToHexString(), "NewBlake256")
        })
    }
}

// ===========

var blake224Tests = []struct {
    output string
    input  string
}{
    {"c8e92d7088ef87c1530aee2ad44dc720cc10589cc2ec58f95a15e51b",
        "The quick brown fox jumps over the lazy dog"},
    {"cfb6848add73e1cb47994c4765df33b8f973702705a30a71fe4747a3",
        "BLAKE"},
}

func Test_Blake224(t *testing.T) {
    assert := assertT(t)
    assertError := assertErrorT(t)

    for index, test := range blake224Tests {
        e := FromString(test.input).Blake224()

        t.Run(fmt.Sprintf("Blake224_test_%d", index), func(t *testing.T) {
            assertError(e.Error, "Blake224")
            assert(test.output, e.ToHexString(), "Blake224")
        })
    }
}

func Test_NewBlake224(t *testing.T) {
    assert := assertT(t)
    assertError := assertErrorT(t)

    for index, test := range blake224Tests {
        e := FromString("").NewBlake224().Write([]byte(test.input)).Sum(nil)

        t.Run(fmt.Sprintf("NewBlake224_test_%d", index), func(t *testing.T) {
            assertError(e.Error, "NewBlake224")
            assert(test.output, e.ToHexString(), "NewBlake224")
        })
    }
}
