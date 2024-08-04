package panama

import (
    "testing"

    "github.com/deatil/go-cryptobin/tool/test"
    "github.com/deatil/go-cryptobin/cryptobin/crypto"
)

func Test_Name(t *testing.T) {
    eq := test.AssertEqualT(t)

    eq(Panama.String(), "Panama", "Test_Name")
}

func Test_Panama(t *testing.T) {
    assert := test.AssertEqualT(t)
    assertError := test.AssertErrorT(t)

    data := "test-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-pass"
    cypt := crypto.FromString(data).
        SetKey("dfertf12dfertf12dfertf12dfertf12").
        MultipleBy(Panama).
        Encrypt()
    cyptStr := cypt.ToBase64String()

    assertError(cypt.Error(), "Panama-Encode")

    cyptde := crypto.FromBase64String(cyptStr).
        SetKey("dfertf12dfertf12dfertf12dfertf12").
        MultipleBy(Panama).
        Decrypt()
    cyptdeStr := cyptde.ToString()

    assertError(cyptde.Error(), "Panama-Decode")

    assert(data, cyptdeStr, "Panama-res")
}
