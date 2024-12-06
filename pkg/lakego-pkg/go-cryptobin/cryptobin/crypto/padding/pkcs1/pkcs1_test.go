package pkcs1

import (
    "testing"

    "github.com/deatil/go-cryptobin/tool/test"
    "github.com/deatil/go-cryptobin/cryptobin/crypto"
)

func Test_Name(t *testing.T) {
    eq := test.AssertEqualT(t)

    eq(PKCS1Padding.String(), "PKCS1Padding", "Test_Name")
}

func Test_AesCFBPKCS1Padding(t *testing.T) {
    assert := test.AssertEqualT(t)
    assertError := test.AssertErrorT(t)

    data := "tes1tes1tes1tes1tes1tes1tes1tes1"
    cypt := crypto.FromString(data).
        SetKey("dfyytf1256").
        SetIv("dfertf1256").
        Trivium().
        PaddingBy(PKCS1Padding).
        Encrypt()
    cyptStr := cypt.ToBase64String()

    assertError(cypt.Error(), "Test_AesCFBPKCS1Padding-Encode")

    cyptde := crypto.FromBase64String(cyptStr).
        SetKey("dfyytf1256").
        SetIv("dfertf1256").
        Trivium().
        PaddingBy(PKCS1Padding).
        Decrypt()
    cyptdeStr := cyptde.ToString()

    assertError(cyptde.Error(), "Test_AesCFBPKCS1Padding-Decode")

    assert(cyptdeStr, data, "Test_AesCFBPKCS1Padding")
}
