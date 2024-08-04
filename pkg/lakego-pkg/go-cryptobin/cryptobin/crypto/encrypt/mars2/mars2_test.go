package mars2

import (
    "testing"

    "github.com/deatil/go-cryptobin/tool/test"
    "github.com/deatil/go-cryptobin/cryptobin/crypto"
)

func Test_Name(t *testing.T) {
    eq := test.AssertEqualT(t)

    eq(Mars2.String(), "Mars2", "Test_Name")
}

func Test_Mars2PKCS7Padding(t *testing.T) {
    assert := test.AssertEqualT(t)
    assertError := test.AssertErrorT(t)

    data := "test-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-pass"
    cypt := crypto.FromString(data).
        SetKey("dfertf12dfertf12").
        SetIv("dfertf12dfertf12").
        MultipleBy(Mars2).
        CBC().
        PKCS7Padding().
        Encrypt()
    cyptStr := cypt.ToBase64String()

    assertError(cypt.Error(), "Mars2PKCS7Padding-Encode")

    cyptde := crypto.FromBase64String(cyptStr).
        SetKey("dfertf12dfertf12").
        SetIv("dfertf12dfertf12").
        MultipleBy(Mars2).
        CBC().
        PKCS7Padding().
        Decrypt()
    cyptdeStr := cyptde.ToString()

    assertError(cyptde.Error(), "Mars2PKCS7Padding-Decode")

    assert(data, cyptdeStr, "Mars2PKCS7Padding-res")
}
