package ocb3

import (
    "testing"

    "github.com/deatil/go-cryptobin/tool/test"
    "github.com/deatil/go-cryptobin/cryptobin/crypto"
)

func Test_Name(t *testing.T) {
    eq := test.AssertEqualT(t)

    eq(OCB3.String(), "OCB3", "Test_Name")
}

func Test_AesOCB3(t *testing.T) {
    assert := test.AssertEqualT(t)
    assertError := test.AssertErrorT(t)

    key := "dfertf12dfertf12"
    nonce := "df35tf12df35"
    additional := "123123"

    data := "test-pass"
    cypt := crypto.FromString(data).
        SetKey(key).
        SetIv(nonce).
        Aes().
        ModeBy(OCB3, map[string]any{
            "additional": []byte(additional),
        }).
        Encrypt()
    cyptStr := cypt.ToBase64String()

    assertError(cypt.Error(), "Test_AesOCB3-Encode")

    cyptde := crypto.FromBase64String(cyptStr).
        SetKey(key).
        SetIv(nonce).
        Aes().
        ModeBy(OCB3, map[string]any{
            "additional": []byte(additional),
        }).
        Decrypt()
    cyptdeStr := cyptde.ToString()

    assertError(cyptde.Error(), "Test_AesOCB3-Decode")

    assert(data, cyptdeStr, "Test_AesOCB3")
}
