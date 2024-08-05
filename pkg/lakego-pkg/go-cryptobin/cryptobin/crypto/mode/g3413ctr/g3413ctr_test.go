package g3413ctr

import (
    "testing"

    "github.com/deatil/go-cryptobin/tool/test"
    "github.com/deatil/go-cryptobin/cryptobin/crypto"
)

func Test_Name(t *testing.T) {
    eq := test.AssertEqualT(t)

    eq(G3413CTR.String(), "G3413CTR", "Test_Name")
}

func Test_KuznyechikG3413CTRPKCS7Padding(t *testing.T) {
    assert := test.AssertEqualT(t)
    assertError := test.AssertErrorT(t)

    data := "test-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-pass"
    cypt := crypto.FromString(data).
        SetKey("dfertf12dfertf12dfertf12dfertf12").
        SetIv("dfertf12").
        Kuznyechik().
        ModeBy(G3413CTR).
        PKCS7Padding().
        Encrypt()
    cyptStr := cypt.ToBase64String()

    assertError(cypt.Error(), "Test_KuznyechikG3413CTRPKCS7Padding-Encode")

    cyptde := crypto.FromBase64String(cyptStr).
        SetKey("dfertf12dfertf12dfertf12dfertf12").
        SetIv("dfertf12").
        Kuznyechik().
        ModeBy(G3413CTR).
        PKCS7Padding().
        Decrypt()
    cyptdeStr := cyptde.ToString()

    assertError(cyptde.Error(), "Test_KuznyechikG3413CTRPKCS7Padding-Decode")

    assert(data, cyptdeStr, "Test_KuznyechikG3413CTRPKCS7Padding-res")
}

func Test_KuznyechikG3413CTRPKCS7Padding_2(t *testing.T) {
    assert := test.AssertEqualT(t)
    assertError := test.AssertErrorT(t)

    data := "test-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-pass"
    cypt := crypto.FromString(data).
        SetKey("dfertf12dfertf12dfertf12dfertf12").
        SetIv("dfertf12").
        Kuznyechik().
        ModeBy(G3413CTR, map[string]any{
            "bit_block_size": 8,
        }).
        PKCS7Padding().
        Encrypt()
    cyptStr := cypt.ToBase64String()

    assertError(cypt.Error(), "Test_KuznyechikG3413CTRPKCS7Padding_2-Encode")

    cyptde := crypto.FromBase64String(cyptStr).
        SetKey("dfertf12dfertf12dfertf12dfertf12").
        SetIv("dfertf12").
        Kuznyechik().
        ModeBy(G3413CTR, map[string]any{
            "bit_block_size": 8,
        }).
        PKCS7Padding().
        Decrypt()
    cyptdeStr := cyptde.ToString()

    assertError(cyptde.Error(), "Test_KuznyechikG3413CTRPKCS7Padding_2-Decode")

    assert(data, cyptdeStr, "Test_KuznyechikG3413CTRPKCS7Padding_2-res")
}
