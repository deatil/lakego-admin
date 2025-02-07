package nofb

import (
    "testing"

    "github.com/deatil/go-cryptobin/tool/test"
    "github.com/deatil/go-cryptobin/cryptobin/crypto"
)

func Test_Name(t *testing.T) {
    eq := test.AssertEqualT(t)

    eq(NOFB.String(), "NOFB", "Test_Name")
}

func Test_AesNOFB(t *testing.T) {
    assert := test.AssertEqualT(t)
    assertNoError := test.AssertNoErrorT(t)

    data := "test-pass"
    cypt := crypto.FromString(data).
        SetKey("dfertf12dfertf12").
        SetIv("dfertf12ghnjhyuj").
        Aes().
        ModeBy(NOFB).
        Encrypt()
    cyptStr := cypt.ToBase64String()

    assertNoError(cypt.Error(), "AesNOFB-Encode")

    cyptde := crypto.FromBase64String(cyptStr).
        SetKey("dfertf12dfertf12").
        SetIv("dfertf12ghnjhyuj").
        Aes().
        ModeBy(NOFB).
        Decrypt()
    cyptdeStr := cyptde.ToString()

    assertNoError(cyptde.Error(), "AesNOFB-Decode")

    assert(data, cyptdeStr, "AesNOFB")
}
