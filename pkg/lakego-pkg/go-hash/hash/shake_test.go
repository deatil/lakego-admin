package hash

import (
    "fmt"
    "testing"
)

var testShake128 = []struct {
    output string
    input  string
}{
    {"a451992153eac48ebbba4f1a7f0fc31f6d1abc005e4014e7b8709e65b8ad9975", "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd"},
    {"ecbe3c323060b214f2e9343cbfd3458cb85fc36cb8ab415b44822285d8752d7d", "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabc"},
    {"71a1c65ee464037682d44375fe3cb5eb67933e5d4f32486e697869d1c2d291de", "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabc"},
}

func Test_Shake128(t *testing.T) {
    assert := assertT(t)
    assertError := assertErrorT(t)

    for index, test := range testShake128 {
        e := FromString(test.input).Shake128(32)

        t.Run(fmt.Sprintf("Shake128 %d", index), func(t *testing.T) {
            assertError(e.Error, "Shake128")
            assert(e.ToHexString(), test.output, "Shake128")
        })
    }

    for index, test := range testShake128 {
        e := FromString("").NewShake128().Write([]byte(test.input)).Sum(nil)

        t.Run(fmt.Sprintf("NewShake128 %d", index), func(t *testing.T) {
            assertError(e.Error, "NewShake128")
            assert(e.ToHexString(), test.output, "NewShake128")
        })
    }
}

var testShake256 = []struct {
    output string
    input  string
}{
    {"2905fd32f4eb546c7d8f0ea6ca3b643965df30f941759d138e0ad6706cd3d9b3b1bb2e771b902f4bb582c13b9bab1957b9f83241977fdc637e831afe75ecf9fe", "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd"},
    {"392c2a6ff117a13a0bfa28c9ab80c53003af473168ad0eff538e453555ba64094e9aced4eaec3a2e9b33fde255cd0cabe7b29bde42283029ffda1049168d8cb8", "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabc"},
    {"ee792434fd62dabbf0aa453d4645ff9367c6582fa5f25925e53f0c7dff38f77fd05d1dc0ae79ded8168e631b2175c8bde24ef3f1241356f3f1abf52b6e5c94f1", "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabc"},
}

func Test_Shake256(t *testing.T) {
    assert := assertT(t)
    assertError := assertErrorT(t)

    for index, test := range testShake256 {
        e := FromString(test.input).Shake256(64)

        t.Run(fmt.Sprintf("Shake256 %d", index), func(t *testing.T) {
            assertError(e.Error, "Shake256")
            assert(e.ToHexString(), test.output, "Shake256")
        })
    }

    for index, test := range testShake256 {
        e := FromString("").NewShake256().Write([]byte(test.input)).Sum(nil)

        t.Run(fmt.Sprintf("NewShake256 %d", index), func(t *testing.T) {
            assertError(e.Error, "NewShake256")
            assert(e.ToHexString(), test.output, "NewShake256")
        })
    }
}

var testCShake128 = []struct {
    N, S []byte
    output string
    input  string
}{
    {[]byte("test"), []byte("test2"), "71567806038cb218b3aa99e3dc6c0844bfa3a90ab3e1ab7c35c496a1223e3741", "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd"},
    {[]byte("test"), []byte("test2"), "a6440b1241679c33a6a8e55040b1a8f4efb9909d57ca853538b3c79b41a2e41b", "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabc"},
    {[]byte("test"), []byte("test2"), "f3ccfa48fcd038eb907c82dc3968985ba7a4ca45df0928f5ac79439e9c5495bf", "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabc"},
}

func Test_CShake128(t *testing.T) {
    assert := assertT(t)
    assertError := assertErrorT(t)

    for index, test := range testCShake128 {
        e := FromString(test.input).CShake128(test.N, test.S, 32)

        t.Run(fmt.Sprintf("CShake128 %d", index), func(t *testing.T) {
            assertError(e.Error, "CShake128")
            assert(e.ToHexString(), test.output, "CShake128")
        })
    }

    for index, test := range testCShake128 {
        e := FromString("").NewCShake128(test.N, test.S).Write([]byte(test.input)).Sum(nil)

        t.Run(fmt.Sprintf("NewCShake128 %d", index), func(t *testing.T) {
            assertError(e.Error, "NewCShake128")
            assert(e.ToHexString(), test.output, "NewCShake128")
        })
    }
}

var testCShake256 = []struct {
    N, S []byte
    output string
    input  string
}{
    {[]byte("test"), []byte("test2"), "5d7e5dce7e4c95a6e80543597f3f26a2d295992a9a3ce280302b64bcc35e8c85e6632684a72678cc5c5eb4994b77542e2f7ecbaabeaca643b128a054cdc51209", "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd"},
    {[]byte("test"), []byte("test2"), "faa49ded88204a568eafb2332f5d2913f07c2058aff25f11dff9d681ebca3e7ea00042ccfa32c94681a4de328ddda553df7941c3d7fde35b3eebb4105bc14457", "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabc"},
    {[]byte("test"), []byte("test2"), "725bc604303dd06df2ea9c72de59412437597fcecec28b2e98c98c9c4dcc53674c181a1b1f2d3ab07cac2cb7c7529b024cffd22aa85783721f8fcc56a22cca0c", "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabc"},
}

func Test_CShake256(t *testing.T) {
    assert := assertT(t)
    assertError := assertErrorT(t)

    for index, test := range testCShake256 {
        e := FromString(test.input).CShake256(test.N, test.S, 64)

        t.Run(fmt.Sprintf("CShake256 %d", index), func(t *testing.T) {
            assertError(e.Error, "CShake256")
            assert(e.ToHexString(), test.output, "CShake256")
        })
    }

    for index, test := range testCShake256 {
        e := FromString("").NewCShake256(test.N, test.S).Write([]byte(test.input)).Sum(nil)

        t.Run(fmt.Sprintf("NewCShake256 %d", index), func(t *testing.T) {
            assertError(e.Error, "NewCShake256")
            assert(e.ToHexString(), test.output, "NewCShake256")
        })
    }
}
