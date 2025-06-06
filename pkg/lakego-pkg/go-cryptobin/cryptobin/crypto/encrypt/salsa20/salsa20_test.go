package salsa20

import (
    "testing"

    "github.com/deatil/go-cryptobin/tool/test"
    "github.com/deatil/go-cryptobin/cryptobin/crypto"
)

func Test_Name(t *testing.T) {
    eq := test.AssertEqualT(t)

    eq(Salsa20.String(), "Salsa20", "Test_Name")
}

func Test_Salsa20(t *testing.T) {
    assert := test.AssertEqualT(t)
    assertNoError := test.AssertNoErrorT(t)

    data := "test-pass"
    cypt := crypto.FromString(data).
        SetKey("1234567890abcdef1234567890abcdef").
        SetIv("12abcdef").
        MultipleBy(Salsa20).
        Encrypt()
    cyptStr := cypt.ToBase64String()

    assertNoError(cypt.Error(), "Salsa20-Encode")

    cyptde := crypto.FromBase64String(cyptStr).
        SetKey("1234567890abcdef1234567890abcdef").
        SetIv("12abcdef").
        MultipleBy(Salsa20).
        Decrypt()
    cyptdeStr := cyptde.ToString()

    assertNoError(cyptde.Error(), "Salsa20-Decode")

    assert(data, cyptdeStr, "Salsa20")
}
