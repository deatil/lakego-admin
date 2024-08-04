package square

import (
    "testing"

    "github.com/deatil/go-cryptobin/tool/test"
    "github.com/deatil/go-cryptobin/cryptobin/crypto"
)

func Test_Name(t *testing.T) {
    eq := test.AssertEqualT(t)

    eq(Square.String(), "Square", "Test_Name")
}

func Test_Square(t *testing.T) {
    assert := test.AssertEqualT(t)
    assertError := test.AssertErrorT(t)

    data := "test-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-pass"
    cypt := crypto.FromString(data).
        SetKey("dfertf12dfertf12").
        SetIv("dertf1d2fgtyf12d").
        MultipleBy(Square).
        CBC().
        PKCS7Padding().
        Encrypt()
    cyptStr := cypt.ToBase64String()

    assertError(cypt.Error(), "Square-Encode")

    cyptde := crypto.FromBase64String(cyptStr).
        SetKey("dfertf12dfertf12").
        SetIv("dertf1d2fgtyf12d").
        MultipleBy(Square).
        CBC().
        PKCS7Padding().
        Decrypt()
    cyptdeStr := cyptde.ToString()

    assertError(cyptde.Error(), "Square-Decode")

    assert(cyptdeStr, data, "Square-res")
}
