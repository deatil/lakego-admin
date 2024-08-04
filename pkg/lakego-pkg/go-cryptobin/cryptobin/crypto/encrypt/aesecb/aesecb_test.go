package aesecb

import (
    "testing"

    "github.com/deatil/go-cryptobin/tool/test"
    "github.com/deatil/go-cryptobin/cryptobin/crypto"
)

func Test_Name(t *testing.T) {
    eq := test.AssertEqualT(t)

    eq(AesECB.String(), "AesECB", "Test_Name")
}

func Test_AesECB(t *testing.T) {
    assert := test.AssertEqualT(t)
    assertError := test.AssertErrorT(t)

    data := "test-pass"
    cypt := crypto.FromString(data).
        SetKey("dfertf12dfertf12rtgthytr").
        MultipleBy(AesECB).
        Encrypt()
    cyptStr := cypt.ToBase64String()

    assertError(cypt.Error(), "AesECB-Encode")

    cyptde := crypto.FromBase64String(cyptStr).
        SetKey("dfertf12dfertf12rtgthytr").
        MultipleBy(AesECB).
        Decrypt()
    cyptdeStr := cyptde.ToString()

    assertError(cyptde.Error(), "AesECB-Decode")

    assert(data, cyptdeStr, "AesECB")
}
