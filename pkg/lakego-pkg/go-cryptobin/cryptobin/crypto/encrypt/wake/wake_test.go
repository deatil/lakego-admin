package wake

import (
    "testing"

    "github.com/deatil/go-cryptobin/tool/test"
    "github.com/deatil/go-cryptobin/cryptobin/crypto"
)

func Test_Name(t *testing.T) {
    eq := test.AssertEqualT(t)

    eq(Wake.String(), "Wake", "Test_Name")
}

func Test_WakeNoPadding(t *testing.T) {
    assert := test.AssertEqualT(t)
    assertError := test.AssertErrorT(t)

    data := "test-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-pass"
    cypt := crypto.FromString(data).
        SetKey("dfertf12dfertf12").
        MultipleBy(Wake).
        ECB().
        NoPadding().
        Encrypt()
    cyptStr := cypt.ToBase64String()

    assertError(cypt.Error(), "WakeNoPadding-Encode")

    cyptde := crypto.FromBase64String(cyptStr).
        SetKey("dfertf12dfertf12").
        MultipleBy(Wake).
        ECB().
        NoPadding().
        Decrypt()
    cyptdeStr := cyptde.ToString()

    assertError(cyptde.Error(), "WakeNoPadding-Decode")

    assert(data, cyptdeStr, "WakeNoPadding-res")
}
