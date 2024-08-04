package loki97

import (
    "testing"

    "github.com/deatil/go-cryptobin/tool/test"
    "github.com/deatil/go-cryptobin/cryptobin/crypto"
)

func Test_Name(t *testing.T) {
    eq := test.AssertEqualT(t)

    eq(Loki97.String(), "Loki97", "Test_Name")
}

func Test_Loki97(t *testing.T) {
    eq := test.AssertEqualT(t)

    data := "test-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-pass"
    cyptStr := crypto.FromString(data).
        SetKey("dfertf12dfertfyy").
        SetIv("dfertf12dfertf12").
        MultipleBy(Loki97).
        CFB().
        PKCS7Padding().
        Encrypt().
        ToBase64String()

    cyptdeStr := crypto.FromBase64String(cyptStr).
        SetKey("dfertf12dfertfyy").
        SetIv("dfertf12dfertf12").
        MultipleBy(Loki97).
        CFB().
        PKCS7Padding().
        Decrypt().
        ToString()

    eq(data, cyptdeStr, "Test_Loki97")
}
