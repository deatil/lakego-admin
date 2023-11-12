package hash

import (
    "fmt"
    "testing"
)

var gost34112012256Tests = []struct {
    input  string
    output string
}{
    {"sdfgsdgfsdfg123132", "4f052b73db2dac350fbacd0330b86b425f4c64483426cfde7ff6f1ef8e23b75c"},
    {"dfg.;kp[jewijr0-34lsd", "e71148e43b20070093cefbb6f44a510e8b44eda1016fc2267863f8fb54253ad4"},
    {"123123", "305dd1381bdfc66e966a7c1c9a13e7f72fb7f047ca54996019edbf174a705f7a"},
}

func Test_Gost34112012256(t *testing.T) {
    assert := assertT(t)
    assertError := assertErrorT(t)

    for index, test := range gost34112012256Tests {
        e := FromString(test.input).Gost34112012256()

        t.Run(fmt.Sprintf("Gost34112012256_test_%d", index), func(t *testing.T) {
            assertError(e.Error, "Gost34112012256")
            assert(test.output, e.ToHexString(), "Gost34112012256")
        })
    }
}

func Test_NewGost34112012256(t *testing.T) {
    assert := assertT(t)
    assertError := assertErrorT(t)

    for index, test := range gost34112012256Tests {
        e := FromString("").NewGost34112012256().Write([]byte(test.input)).Sum(nil)

        t.Run(fmt.Sprintf("NewGost34112012256_test_%d", index), func(t *testing.T) {
            assertError(e.Error, "NewGost34112012256")
            assert(test.output, e.ToHexString(), "NewGost34112012256")
        })
    }
}

// ==============

var gost34112012512Tests = []struct {
    input  string
    output string
}{
    {"sdfgsdgfsdfg123132", "091b85de942388bec2735ffe9086dc30622b6091881fe7458192a5173482ee6c8fa5e07970898279a391171d62671711c96fb6309f7667507f0bc7d9d08adef8"},
    {"dfg.;kp[jewijr0-34lsd", "58775fed6bf929f5523fd370d6b3fb3deca8713598877a176de3188467a9299b3818e01ca7b5f38e32c71a8d10515358a42e25e598554471e45c5ba489ebf86e"},
    {"123123", "e3f3e7189ba0971cf68465bef1ad7d0921e0b4205afa72205e4fa81755f14655d50a83763992d5f785ea70e5d0273c11295d9d96dacc4ab99885ef59dae2a1d8"},
}

func Test_Gost34112012512(t *testing.T) {
    assert := assertT(t)
    assertError := assertErrorT(t)

    for index, test := range gost34112012512Tests {
        e := FromString(test.input).Gost34112012512()

        t.Run(fmt.Sprintf("Gost34112012512_test_%d", index), func(t *testing.T) {
            assertError(e.Error, "Gost34112012512")
            assert(test.output, e.ToHexString(), "Gost34112012512")
        })
    }
}

func Test_NewGost34112012512(t *testing.T) {
    assert := assertT(t)
    assertError := assertErrorT(t)

    for index, test := range gost34112012512Tests {
        e := FromString("").NewGost34112012512().Write([]byte(test.input)).Sum(nil)

        t.Run(fmt.Sprintf("NewGost34112012512_test_%d", index), func(t *testing.T) {
            assertError(e.Error, "NewGost34112012512")
            assert(test.output, e.ToHexString(), "NewGost34112012512")
        })
    }
}

