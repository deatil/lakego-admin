package aescfb

import (
    "testing"

    "github.com/deatil/go-cryptobin/tool/test"
    "github.com/deatil/go-cryptobin/cryptobin/crypto"
)

func Test_Name(t *testing.T) {
    eq := test.AssertEqualT(t)

    eq(AesCFB.String(), "AesCFB", "Test_Name")
}

func Test_AesCFB(t *testing.T) {
    assert := test.AssertEqualT(t)
    assertNoError := test.AssertNoErrorT(t)

    data := "test-pass"
    cypt := crypto.FromString(data).
        SetKey("dfertf12dfertf12").
        MultipleBy(AesCFB).
        Encrypt()
    cyptStr := cypt.ToBase64String()

    assertNoError(cypt.Error(), "AesCFB-Encode")

    cyptde := crypto.FromBase64String(cyptStr).
        SetKey("dfertf12dfertf12").
        MultipleBy(AesCFB).
        Decrypt()
    cyptdeStr := cyptde.ToString()

    assertNoError(cyptde.Error(), "AesCFB-Decode")

    assert(data, cyptdeStr, "AesCFB")
}
