package enigma

import (
    "testing"

    "github.com/deatil/go-cryptobin/tool/test"
    "github.com/deatil/go-cryptobin/cryptobin/crypto"
)

func Test_Name(t *testing.T) {
    eq := test.AssertEqualT(t)

    eq(Enigma.String(), "Enigma", "Test_Name")
}

func Test_Enigma(t *testing.T) {
    assert := test.AssertEqualT(t)
    assertNoError := test.AssertNoErrorT(t)

    data := "test-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-pass"
    cypt := crypto.FromString(data).
        SetKey("dfertf12dfert").
        MultipleBy(Enigma).
        Encrypt()
    cyptStr := cypt.ToBase64String()

    assertNoError(cypt.Error(), "EnigmaNoPadding-Encode")

    cyptde := crypto.FromBase64String(cyptStr).
        SetKey("dfertf12dfert").
        MultipleBy(Enigma).
        Decrypt()
    cyptdeStr := cyptde.ToString()

    assertNoError(cyptde.Error(), "EnigmaNoPadding-Decode")

    assert(data, cyptdeStr, "EnigmaNoPadding-res")
}
