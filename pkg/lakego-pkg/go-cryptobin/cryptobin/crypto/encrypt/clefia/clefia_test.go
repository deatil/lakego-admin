package clefia

import (
    "testing"

    "github.com/deatil/go-cryptobin/tool/test"
    "github.com/deatil/go-cryptobin/cryptobin/crypto"
)

func Test_Name(t *testing.T) {
    eq := test.AssertEqualT(t)

    eq(Clefia.String(), "Clefia", "Test_Name")
}

func Test_Clefia(t *testing.T) {
    assert := test.AssertEqualT(t)
    assertNoError := test.AssertNoErrorT(t)

    data := "test-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-pass"
    cypt := crypto.FromString(data).
        SetKey("dfertf1d2fgtyf35").
        SetIv("dfertf1d2fgtyfdf").
        MultipleBy(Clefia).
        CBC().
        PKCS7Padding().
        Encrypt()
    cyptStr := cypt.ToBase64String()

    assertNoError(cypt.Error(), "Clefia-Encode")

    cyptde := crypto.FromBase64String(cyptStr).
        SetKey("dfertf1d2fgtyf35").
        SetIv("dfertf1d2fgtyfdf").
        MultipleBy(Clefia).
        CBC().
        PKCS7Padding().
        Decrypt()
    cyptdeStr := cyptde.ToString()

    assertNoError(cyptde.Error(), "Clefia-Decode")

    assert(cyptdeStr, data, "Clefia-res")
}
