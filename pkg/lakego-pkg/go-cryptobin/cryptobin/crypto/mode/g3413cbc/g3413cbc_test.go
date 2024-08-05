package g3413cbc

import (
    "testing"

    "github.com/deatil/go-cryptobin/tool/test"
    "github.com/deatil/go-cryptobin/cryptobin/crypto"
)

func Test_Name(t *testing.T) {
    eq := test.AssertEqualT(t)

    eq(G3413CBC.String(), "G3413CBC", "Test_Name")
}

func Test_KuznyechikG3413CBCPKCS7Padding(t *testing.T) {
    assert := test.AssertEqualT(t)
    assertError := test.AssertErrorT(t)

    data := "test-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-pass"
    cypt := crypto.FromString(data).
        SetKey("dfertf12dfertf12dfertf12dfertf12").
        SetIv("dfertf12dfertf12dfertf12dfertf12").
        Kuznyechik().
        ModeBy(G3413CBC).
        PKCS7Padding().
        Encrypt()
    cyptStr := cypt.ToBase64String()

    assertError(cypt.Error(), "Test_KuznyechikG3413CBCPKCS7Padding-Encode")

    cyptde := crypto.FromBase64String(cyptStr).
        SetKey("dfertf12dfertf12dfertf12dfertf12").
        SetIv("dfertf12dfertf12dfertf12dfertf12").
        Kuznyechik().
        ModeBy(G3413CBC).
        PKCS7Padding().
        Decrypt()
    cyptdeStr := cyptde.ToString()

    assertError(cyptde.Error(), "Test_KuznyechikG3413CBCPKCS7Padding-Decode")

    assert(data, cyptdeStr, "Test_KuznyechikG3413CBCPKCS7Padding-res")
}
