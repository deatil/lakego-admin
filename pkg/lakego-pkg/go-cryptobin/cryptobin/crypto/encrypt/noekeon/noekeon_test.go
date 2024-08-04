package noekeon

import (
    "testing"

    "github.com/deatil/go-cryptobin/tool/test"
    "github.com/deatil/go-cryptobin/cryptobin/crypto"
)

func Test_Name(t *testing.T) {
    eq := test.AssertEqualT(t)

    eq(Noekeon.String(), "Noekeon", "Test_Name")
}

func Test_Noekeon(t *testing.T) {
    assert := test.AssertEqualT(t)
    assertError := test.AssertErrorT(t)

    data := "test-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-pass"
    cypt := crypto.FromString(data).
        SetKey("dfertf1d2fgtyf35").
        SetIv("dfertf1d2fgtyfdf").
        MultipleBy(Noekeon).
        CBC().
        PKCS7Padding().
        Encrypt()
    cyptStr := cypt.ToBase64String()

    assertError(cypt.Error(), "Noekeon-Encode")

    cyptde := crypto.FromBase64String(cyptStr).
        SetKey("dfertf1d2fgtyf35").
        SetIv("dfertf1d2fgtyfdf").
        MultipleBy(Noekeon).
        CBC().
        PKCS7Padding().
        Decrypt()
    cyptdeStr := cyptde.ToString()

    assertError(cyptde.Error(), "Noekeon-Decode")

    assert(cyptdeStr, data, "Noekeon-res")
}
