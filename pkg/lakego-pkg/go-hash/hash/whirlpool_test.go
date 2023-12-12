package hash

import (
    "fmt"
    "bytes"
    "testing"
)

var whirlpoolTests = []struct {
    input  string
    output string
}{
    {"abcdefghij", "717163de24809ffcf7ff6d5aba72b8d67c2129721953c252a4ddfb107614be857cbd76a9d5927de14633d6bdc9ddf335160b919db5c6f12cb2e6549181912eef"},
}

func Test_Whirlpool(t *testing.T) {
    assert := assertT(t)
    assertError := assertErrorT(t)

    for index, test := range whirlpoolTests {
        e := FromString(test.input).Whirlpool()

        t.Run(fmt.Sprintf("whirlpool_test_%d", index), func(t *testing.T) {
            assertError(e.Error, "Whirlpool")
            assert(test.output, e.ToHexString(), "Whirlpool")
        })
    }
}

func Test_NewWhirlpool(t *testing.T) {
    assert := assertT(t)
    assertError := assertErrorT(t)

    for index, test := range whirlpoolTests {
        e := Hashing().NewWhirlpool().Write([]byte(test.input)).Sum(nil)

        t.Run(fmt.Sprintf("NewWhirlpool_test_%d", index), func(t *testing.T) {
            assertError(e.Error, "NewWhirlpool")
            assert(test.output, e.ToHexString(), "NewWhirlpool")
        })
    }
}

func Test_NewWhirlpool_WriteReader(t *testing.T) {
    assert := assertT(t)
    assertError := assertErrorT(t)

    for index, test := range whirlpoolTests {
        buf := bytes.NewBuffer([]byte(test.input))

        e := Hashing().NewWhirlpool().WriteReader(buf).Sum(nil)

        t.Run(fmt.Sprintf("NewWhirlpool_WriteReader_test_%d", index), func(t *testing.T) {
            assertError(e.Error, "NewWhirlpool_WriteReader")
            assert(test.output, e.ToHexString(), "NewWhirlpool_WriteReader")
        })
    }
}
