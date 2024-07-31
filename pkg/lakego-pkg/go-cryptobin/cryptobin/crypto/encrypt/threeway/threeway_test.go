package threeway

import (
    "testing"

    "github.com/deatil/go-cryptobin/tool/test"
    "github.com/deatil/go-cryptobin/cryptobin/crypto"
)

func Test_Name(t *testing.T) {
    eq := test.AssertEqualT(t)

    eq(Threeway.String(), "Threeway", "Test_Name")
}

func Test_ThreewayPKCS7Padding(t *testing.T) {
    eq := test.AssertEqualT(t)

    data := "test-pass"
    cyptStr := crypto.FromString(data).
        SetKey("dfertf12dfyy").
        SetIv("dfertf12dfer").
        WithMultiple(Threeway).
        CFB().
        PKCS7Padding().
        Encrypt().
        ToBase64String()

    cyptdeStr := crypto.FromBase64String(cyptStr).
        SetKey("dfertf12dfyy").
        SetIv("dfertf12dfer").
        WithMultiple(Threeway).
        CFB().
        PKCS7Padding().
        Decrypt().
        ToString()

    eq(data, cyptdeStr, "Test_ThreewayPKCS7Padding")
}
