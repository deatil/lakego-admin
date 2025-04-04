package magenta

import (
    "testing"

    "github.com/deatil/go-cryptobin/tool/test"
    "github.com/deatil/go-cryptobin/cryptobin/crypto"
)

func Test_Name(t *testing.T) {
    eq := test.AssertEqualT(t)

    eq(Magenta.String(), "Magenta", "Test_Name")
}

func Test_Magenta(t *testing.T) {
    assert := test.AssertEqualT(t)
    assertNoError := test.AssertNoErrorT(t)

    data := "test-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-pass"
    cypt := crypto.FromString(data).
        SetKey("dfertf12dfertf12dfertf12dfertf12").
        SetIv("dfertf1d2fgtyf12").
        MultipleBy(Magenta).
        CBC().
        PKCS7Padding().
        Encrypt()
    cyptStr := cypt.ToBase64String()

    assertNoError(cypt.Error(), "Magenta-Encode")

    cyptde := crypto.FromBase64String(cyptStr).
        SetKey("dfertf12dfertf12dfertf12dfertf12").
        SetIv("dfertf1d2fgtyf12").
        MultipleBy(Magenta).
        CBC().
        PKCS7Padding().
        Decrypt()
    cyptdeStr := cyptde.ToString()

    assertNoError(cyptde.Error(), "Magenta-Decode")

    assert(cyptdeStr, data, "Magenta-res")
}
