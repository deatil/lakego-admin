package anubis

import (
    "testing"

    "github.com/deatil/go-cryptobin/tool/test"
    "github.com/deatil/go-cryptobin/cryptobin/crypto"
)

func Test_Name(t *testing.T) {
    eq := test.AssertEqualT(t)

    eq(Anubis.String(), "Anubis", "Test_Name")
}

func Test_Anubis(t *testing.T) {
    assert := test.AssertEqualT(t)
    assertError := test.AssertErrorT(t)

    data := "test-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-pass"
    cypt := crypto.FromString(data).
        SetKey("dfertf1d2fgtyf35").
        SetIv("dfertf1dfvb5gtyh").
        MultipleBy(Anubis).
        CBC().
        PKCS7Padding().
        Encrypt()
    cyptStr := cypt.ToBase64String()

    assertError(cypt.Error(), "Anubis-Encode")

    cyptde := crypto.FromBase64String(cyptStr).
        SetKey("dfertf1d2fgtyf35").
        SetIv("dfertf1dfvb5gtyh").
        MultipleBy(Anubis).
        CBC().
        PKCS7Padding().
        Decrypt()
    cyptdeStr := cyptde.ToString()

    assertError(cyptde.Error(), "Anubis-Decode")

    assert(cyptdeStr, data, "Anubis-res")
}
