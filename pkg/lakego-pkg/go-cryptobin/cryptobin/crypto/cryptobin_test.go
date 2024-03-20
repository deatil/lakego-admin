package crypto

import (
    "fmt"
    "testing"
    "crypto/md5"
    "encoding/hex"
    "encoding/base64"

    cryptobin_test "github.com/deatil/go-cryptobin/tool/test"
)

func Test_FuncEncrypt(t *testing.T) {
    assert := cryptobin_test.AssertEqualT(t)

    data := "test-pass"
    cyptStr := FromString(data).
        FuncEncrypt(func(c Cryptobin) Cryptobin {
            res := base64.StdEncoding.EncodeToString(c.GetData())

            return c.SetParsedData(res)
        }).
        Encrypt().
        ToBase64String()

    cyptdeStr := FromBase64String(cyptStr).
        FuncDecrypt(func(c Cryptobin) Cryptobin {
            res, err := base64.StdEncoding.DecodeString(string(c.GetData()))
            if err != nil {
                return c.AppendError(err)
            }

            return c.SetParsedData(string(res))
        }).
        Decrypt().
        ToString()

    assert(data, cyptdeStr, "Test_FuncEncrypt")
}

func Test_TripleDesPKCS7Padding(t *testing.T) {
    assert := cryptobin_test.AssertEqualT(t)

    data := "test-pass"
    cyptStr := FromString(data).
        SetKey("dfertf12dfertf12dfertf12").
        SetIv("dfertf12").
        TripleDes().
        CFB().
        PKCS7Padding().
        Encrypt().
        ToBase64String()

    cyptdeStr := FromBase64String(cyptStr).
        SetKey("dfertf12dfertf12dfertf12").
        SetIv("dfertf12").
        TripleDes().
        CFB().
        PKCS7Padding().
        Decrypt().
        ToString()

    assert(data, cyptdeStr, "TripleDesPKCS7Padding")
}

func Test_AesECBPKCS5Padding(t *testing.T) {
    assert := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    data := "test-pass"
    cypt := FromString(data).
        SetKey("dfertf12dfertf12").
        Aes().
        ECB().
        PKCS5Padding().
        Encrypt()
    cyptStr := cypt.ToBase64String()

    assertError(cypt.Error(), "AesECBPKCS5Padding-Encode")

    cyptde := FromBase64String(cyptStr).
        SetKey("dfertf12dfertf12").
        Aes().
        ECB().
        PKCS5Padding().
        Decrypt()
    cyptdeStr := cyptde.ToString()

    assertError(cyptde.Error(), "AesECBPKCS5Padding-Decode")

    assert(data, cyptdeStr, "AesECBPKCS5Padding")
}

func Test_SM4ECBPKCS7Padding(t *testing.T) {
    assert := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    data := "test-pass"
    cypt := FromString(data).
        SetKey("1234567890abcdef").
        SM4().
        ECB().
        PKCS7Padding().
        Encrypt()
    cyptStr := cypt.ToBase64String()

    assertError(cypt.Error(), "SM4ECBPKCS7Padding-Encode")

    cyptde := FromBase64String(cyptStr).
        SetKey("1234567890abcdef").
        SM4().
        ECB().
        PKCS7Padding().
        Decrypt()
    cyptdeStr := cyptde.ToString()

    assertError(cyptde.Error(), "SM4ECBPKCS7Padding-Decode")

    assert(data, cyptdeStr, "SM4ECBPKCS7Padding")
}

func Test_XtsPKCS5Padding(t *testing.T) {
    assert := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    data := "test-pass"
    cypt := FromString(data).
        SetKey("1234567890abcdef1234567890abcdef").
        Xts("Aes", 0x3333333333).
        // PaddingBy(PKCS5Padding).
        PKCS5Padding().
        Encrypt()
    cyptStr := cypt.ToHexString()

    assertError(cypt.Error(), "XtsPKCS5Padding-Encode")

    cyptde := FromHexString(cyptStr).
        SetKey("1234567890abcdef1234567890abcdef").
        // PaddingBy(PKCS5Padding).
        PKCS5Padding().
        Xts("Aes", 0x3333333333).
        Decrypt()
    cyptdeStr := cyptde.ToString()

    assertError(cyptde.Error(), "XtsPKCS5Padding-Decode")

    assert(data, cyptdeStr, "XtsPKCS5Padding")
}

func Test_AesCFB(t *testing.T) {
    assert := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    data := "test-pass"
    cypt := FromString(data).
        SetKey("dfertf12dfertf12").
        AesCFB().
        Encrypt()
    cyptStr := cypt.ToBase64String()

    assertError(cypt.Error(), "AesCFB-Encode")

    cyptde := FromBase64String(cyptStr).
        SetKey("dfertf12dfertf12").
        AesCFB().
        Decrypt()
    cyptdeStr := cyptde.ToString()

    assertError(cyptde.Error(), "AesCFB-Decode")

    assert(data, cyptdeStr, "AesCFB")
}

func Test_AesECB(t *testing.T) {
    assert := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    data := "test-pass"
    cypt := FromString(data).
        SetKey("dfertf12dfertf12rtgthytr").
        AesECB().
        Encrypt()
    cyptStr := cypt.ToBase64String()

    assertError(cypt.Error(), "AesECB-Encode")

    cyptde := FromBase64String(cyptStr).
        SetKey("dfertf12dfertf12rtgthytr").
        AesECB().
        Decrypt()
    cyptdeStr := cyptde.ToString()

    assertError(cyptde.Error(), "AesECB-Decode")

    assert(data, cyptdeStr, "AesECB")
}

func Test_AesCFB1PKCS7Padding(t *testing.T) {
    assert := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    data := "test-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-pass"
    cypt := FromString(data).
        SetKey("dfertf12dfertf12").
        SetIv("dfertf12dfertf12").
        Aes().
        CFB1().
        PKCS7Padding().
        Encrypt()
    cyptStr := cypt.ToBase64String()

    assertError(cypt.Error(), "AesCFB1PKCS7Padding-Encode")

    cyptde := FromBase64String(cyptStr).
        SetKey("dfertf12dfertf12").
        SetIv("dfertf12dfertf12").
        Aes().
        CFB1().
        PKCS7Padding().
        Decrypt()
    cyptdeStr := cyptde.ToString()

    assertError(cyptde.Error(), "AesCFB1PKCS7Padding-Decode")

    assert(data, cyptdeStr, "AesCFB1PKCS7Padding")

    // 根据具体数据测试
    encrypted := "CaszhS+Z7fsGvHgarlePOC3VumYR+LZbKiI3xuIk8yvX2NK1Wm7dFpysTvmTCJy3F1UOZaxSDVcbZk+s2lgSVzZ/14L90RB1q3+z8goz8gleb6G2ZKOgWYwby1g87ONrsNGz0IlG8YCI0iGzyE3U3DitLqRP/l9eYhHZXtnBSq1iZHyJ2BvI54YWTowmKqsDvPQkUicTUIHGziqvVsIHFy2ngT2uBvmBOIlYMkBwce20kaMfIHsmlGXMNHKcVBGS"
    cyptde2 := FromBase64String(encrypted).
        SetKey("dfertf12dfertf12").
        SetIv("dfertf12dfertf12").
        Aes().
        CFB1().
        PKCS7Padding().
        Decrypt()
    cyptdeStr2 := cyptde2.ToString()

    assertError(cyptde2.Error(), "AesCFB1PKCS7Padding-2-Decode")

    assert("pass-datapass-datapass-datapass-datapass-datapass-datapass-datapass-datapass-datapass-datapass-datapass-datapass-datapass-datapass-datapass-datapass-datapass-datapass-datapass-datapass-data", cyptdeStr2, "AesCFB1PKCS7Padding-2")
}

func Test_AesCFB16PKCS7Padding(t *testing.T) {
    assert := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    data := "test-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-pass"
    cypt := FromString(data).
        SetKey("dfertf12dfertf12").
        SetIv("dfertf12dfertf12").
        Aes().
        CFB16().
        PKCS7Padding().
        Encrypt()
    cyptStr := cypt.ToBase64String()

    assertError(cypt.Error(), "AesCFB16PKCS7Padding-Encode")

    cyptde := FromBase64String(cyptStr).
        SetKey("dfertf12dfertf12").
        SetIv("dfertf12dfertf12").
        Aes().
        CFB16().
        PKCS7Padding().
        Decrypt()
    cyptdeStr := cyptde.ToString()

    assertError(cyptde.Error(), "AesCFB16PKCS7Padding-Decode")

    assert(data, cyptdeStr, "AesCFB16PKCS7Padding")
}

func Test_AesCFB32PKCS7Padding(t *testing.T) {
    assert := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    data := "test-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-pass"
    cypt := FromString(data).
        SetKey("dfertf12dfertf12").
        SetIv("dfertf12dfertf12").
        Aes().
        CFB32().
        PKCS7Padding().
        Encrypt()
    cyptStr := cypt.ToBase64String()

    assertError(cypt.Error(), "AesCFB32PKCS7Padding-Encode")

    cyptde := FromBase64String(cyptStr).
        SetKey("dfertf12dfertf12").
        SetIv("dfertf12dfertf12").
        Aes().
        CFB32().
        PKCS7Padding().
        Decrypt()
    cyptdeStr := cyptde.ToString()

    assertError(cyptde.Error(), "AesCFB32PKCS7Padding-Decode")

    assert(data, cyptdeStr, "AesCFB32PKCS7Padding")
}

func Test_AesCFB64PKCS7Padding(t *testing.T) {
    assert := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    data := "test-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-pass"
    cypt := FromString(data).
        SetKey("dfertf12dfertf12").
        SetIv("dfertf12dfertf12").
        Aes().
        CFB64().
        PKCS7Padding().
        Encrypt()
    cyptStr := cypt.ToBase64String()

    assertError(cypt.Error(), "AesCFB64PKCS7Padding-Encode")

    cyptde := FromBase64String(cyptStr).
        SetKey("dfertf12dfertf12").
        SetIv("dfertf12dfertf12").
        Aes().
        CFB64().
        PKCS7Padding().
        Decrypt()
    cyptdeStr := cyptde.ToString()

    assertError(cyptde.Error(), "AesCFB64PKCS7Padding-Decode")

    assert(data, cyptdeStr, "AesCFB64PKCS7Padding")
}

func Test_AesCFB128PKCS7Padding(t *testing.T) {
    assert := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    data := "test-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-pass"
    cypt := FromString(data).
        SetKey("dfertf12dfertf12").
        SetIv("dfertf12dfertf12").
        Aes().
        CFB128().
        PKCS7Padding().
        Encrypt()
    cyptStr := cypt.ToBase64String()

    assertError(cypt.Error(), "AesCFB128PKCS7Padding-Encode")

    cyptde := FromBase64String(cyptStr).
        SetKey("dfertf12dfertf12").
        SetIv("dfertf12dfertf12").
        Aes().
        CFB128().
        PKCS7Padding().
        Decrypt()
    cyptdeStr := cyptde.ToString()

    assertError(cyptde.Error(), "AesCFB128PKCS7Padding-Decode")

    assert(data, cyptdeStr, "AesCFB128PKCS7Padding")
}

func Test_AesPCBCPKCS7Padding(t *testing.T) {
    assert := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    data := "test-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-pass"
    cypt := FromString(data).
        SetKey("dfertf12dfertf12").
        SetIv("dfertf12dfertf12").
        Aes().
        PCBC().
        PKCS7Padding().
        Encrypt()
    cyptStr := cypt.ToBase64String()

    assertError(cypt.Error(), "AesPCBCPKCS7Padding-Encode")

    cyptde := FromBase64String(cyptStr).
        SetKey("dfertf12dfertf12").
        SetIv("dfertf12dfertf12").
        Aes().
        PCBC().
        PKCS7Padding().
        Decrypt()
    cyptdeStr := cyptde.ToString()

    assertError(cyptde.Error(), "AesPCBCPKCS7Padding-Decode")

    assert(data, cyptdeStr, "AesPCBCPKCS7Padding")

    // 具体数据
    src := "3y41ewE+O/VnVNIdRw2fp5HrqLekui64UAyKeZ0D0IH/3qXABrRXcG/Noizyzy5kMUOCwGrXFpTu7YgYakadznidUPENgxV8IPwaHF/G0eFVKScRLWJsGEE0NAqp075ea1ZZDA0jpB6NYs/5Y3T0fMcaXOx3eq7Gbt/trP3fSuPURID8eK8yr2UL9wRK7LV0i4f0AtT3Z/kmO0D6npRmD4m6nXKPck5mE56yRTyNI05f67Ifa7wF97Uceb/JHQwUugIPamE3C+JUVz8B+UHP93A6rU45+tGBpIh/zIKYqKtr3nUGsVzxdxr4MT1ciWws1mef1kzbedLrn7SXLEaptQ=="
    // src := "bfd68ecd4a9bb4be0a3ebe5bdb7a09553fbdb7bfa3b5c345568beefd67d79c1b"
    cyptde2 := // FromHexString(src).
        FromBase64String(src).
        SetKey("dfertf12dfertf12").
        SetIv("dfertf12dfertf12").
        Aes().
        PCBC().
        PKCS7Padding().
        Decrypt()
    cyptdeStr2 := cyptde2.ToString()

    assertError(cyptde2.Error(), "AesPCBCPKCS7Padding-Decode")

    // testdata := "test-passtest-passtest-pass"
    testdata := "test-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-pass"
    assert(testdata, cyptdeStr2, "AesPCBCPKCS7Padding")
}

func Test_TwoDesCFBPKCS7Padding(t *testing.T) {
    assert := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    data := "test-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-pass"
    cypt := FromString(data).
        SetKey("dfertf12dfertf12").
        SetIv("jifu87uj").
        TwoDes().
        CFB().
        PKCS7Padding().
        Encrypt()
    cyptStr := cypt.ToBase64String()

    assertError(cypt.Error(), "TwoDesCFBPKCS7Padding-Encode")

    cyptde := FromBase64String(cyptStr).
        SetKey("dfertf12dfertf12").
        SetIv("jifu87uj").
        TwoDes().
        CFB().
        PKCS7Padding().
        Decrypt()
    cyptdeStr := cyptde.ToString()

    assertError(cyptde.Error(), "TwoDesCFBPKCS7Padding-Decode")

    assert(data, cyptdeStr, "TwoDesCFBPKCS7Padding")
}

func Test_IdeaCBCPKCS7Padding(t *testing.T) {
    assert := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    data := "test-pass"
    cypt := FromString(data).
        SetKey("1234567890abcdef").
        SetIv("jifu87uj").
        Idea().
        CBC().
        PKCS7Padding().
        Encrypt()
    cyptStr := cypt.ToBase64String()

    assertError(cypt.Error(), "IdeaCBCPKCS7Padding-Encode")

    cyptde := FromBase64String(cyptStr).
        SetKey("1234567890abcdef").
        SetIv("jifu87uj").
        Idea().
        CBC().
        PKCS7Padding().
        Decrypt()
    cyptdeStr := cyptde.ToString()

    assertError(cyptde.Error(), "IdeaCBCPKCS7Padding-Decode")

    assert(data, cyptdeStr, "IdeaCBCPKCS7Padding")
}

func Test_RC4MD5(t *testing.T) {
    assert := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    data := "test-pass"
    cypt := FromString(data).
        SetKey("1234567890abcdef").
        SetIv("jifu87uj").
        RC4MD5().
        Encrypt()
    cyptStr := cypt.ToBase64String()

    assertError(cypt.Error(), "RC4MD5-Encode")

    cyptde := FromBase64String(cyptStr).
        SetKey("1234567890abcdef").
        SetIv("jifu87uj").
        RC4MD5().
        Decrypt()
    cyptdeStr := cyptde.ToString()

    assertError(cyptde.Error(), "RC4MD5-Decode")

    assert(data, cyptdeStr, "RC4MD5")
}

func Test_Salsa20(t *testing.T) {
    assert := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    data := "test-pass"
    cypt := FromString(data).
        SetKey("1234567890abcdef1234567890abcdef").
        SetIv("1234567890abcdef").
        Salsa20().
        Encrypt()
    cyptStr := cypt.ToBase64String()

    assertError(cypt.Error(), "Salsa20-Encode")

    cyptde := FromBase64String(cyptStr).
        SetKey("1234567890abcdef1234567890abcdef").
        SetIv("1234567890abcdef").
        Salsa20().
        Decrypt()
    cyptdeStr := cyptde.ToString()

    assertError(cyptde.Error(), "Salsa20-Decode")

    assert(data, cyptdeStr, "Salsa20")
}

func Test_SeedCFBPKCS7Padding(t *testing.T) {
    assert := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    data := "test-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-pass"
    cypt := FromString(data).
        SetKey("dfertf12dfertf12").
        SetIv("jifu87ujjifu87uj").
        Seed().
        CFB().
        PKCS7Padding().
        Encrypt()
    cyptStr := cypt.ToBase64String()

    assertError(cypt.Error(), "SeedCFBPKCS7Padding-Encode")

    cyptde := FromBase64String(cyptStr).
        SetKey("dfertf12dfertf12").
        SetIv("jifu87ujjifu87uj").
        Seed().
        CFB().
        PKCS7Padding().
        Decrypt()
    cyptdeStr := cyptde.ToString()

    assertError(cyptde.Error(), "SeedCFBPKCS7Padding-Decode")

    assert(data, cyptdeStr, "SeedCFBPKCS7Padding")
}

func Test_AriaCFBPKCS7Padding(t *testing.T) {
    assert := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    data := "test-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-pass"
    cypt := FromString(data).
        SetKey("dfertf12dfertf12dfertf12").
        SetIv("jifu87ujjifu87uj").
        Aria().
        CFB().
        PKCS7Padding().
        Encrypt()
    cyptStr := cypt.ToBase64String()

    assertError(cypt.Error(), "AriaCFBPKCS7Padding-Encode")

    cyptde := FromBase64String(cyptStr).
        SetKey("dfertf12dfertf12dfertf12").
        SetIv("jifu87ujjifu87uj").
        Aria().
        CFB().
        PKCS7Padding().
        Decrypt()
    cyptdeStr := cyptde.ToString()

    assertError(cyptde.Error(), "AriaCFBPKCS7Padding-Decode")

    assert(data, cyptdeStr, "AriaCFBPKCS7Padding")
}

func Test_CamelliaCFBPKCS7Padding(t *testing.T) {
    assert := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    data := "test-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-pass"
    cypt := FromString(data).
        SetKey("dfertf12dfertf12dfertf12").
        SetIv("jifu87ujjifu87uj").
        Camellia().
        CFB().
        PKCS7Padding().
        Encrypt()
    cyptStr := cypt.ToBase64String()

    assertError(cypt.Error(), "CamelliaCFBPKCS7Padding-Encode")

    cyptde := FromBase64String(cyptStr).
        SetKey("dfertf12dfertf12dfertf12").
        SetIv("jifu87ujjifu87uj").
        Camellia().
        CFB().
        PKCS7Padding().
        Decrypt()
    cyptdeStr := cyptde.ToString()

    assertError(cyptde.Error(), "CamelliaCFBPKCS7Padding-Decode")

    assert(data, cyptdeStr, "CamelliaCFBPKCS7Padding")
}

func gostCFBPKCS7PaddingWithSbox(t *testing.T, sbox string) {
    assert := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    data := "test-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-pass"
    cypt := FromString(data).
        SetKey("dfertf12dfertf12dfertf12dfertf12").
        SetIv("jifu87uj").
        Gost(sbox).
        CFB().
        PKCS7Padding().
        Encrypt()
    cyptStr := cypt.ToBase64String()

    assertError(cypt.Error(), "GostCFBPKCS7Padding-Encode-" + sbox)

    cyptde := FromBase64String(cyptStr).
        SetKey("dfertf12dfertf12dfertf12dfertf12").
        SetIv("jifu87uj").
        Gost(sbox).
        CFB().
        PKCS7Padding().
        Decrypt()
    cyptdeStr := cyptde.ToString()

    assertError(cyptde.Error(), "GostCFBPKCS7Padding-Decode-" + sbox)

    assert(data, cyptdeStr, "GostCFBPKCS7Padding-" + sbox)
}

func Test_GostCFBPKCS7Padding(t *testing.T) {
    sboxs := []string{
        "SboxDESDerivedParamSet",
        "SboxRFC4357TestParamSet",
        "SboxGostR341194CryptoProParamSet",
        "SboxTC26gost28147paramZ",
        "SboxEACParamSet",
    }

    for _, sbox := range sboxs {
        gostCFBPKCS7PaddingWithSbox(t, sbox)
    }
}

func Test_KuznyechikCFBPKCS7Padding(t *testing.T) {
    assert := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    data := "test-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-pass"
    cypt := FromString(data).
        SetKey("dfertf12dfertf12dfertf12dfertf12").
        SetIv("jifu87ujjifu87uj").
        Kuznyechik().
        CFB().
        PKCS7Padding().
        Encrypt()
    cyptStr := cypt.ToBase64String()

    assertError(cypt.Error(), "KuznyechikCFBPKCS7Padding-Encode")

    cyptde := FromBase64String(cyptStr).
        SetKey("dfertf12dfertf12dfertf12dfertf12").
        SetIv("jifu87ujjifu87uj").
        Kuznyechik().
        CFB().
        PKCS7Padding().
        Decrypt()
    cyptdeStr := cyptde.ToString()

    assertError(cyptde.Error(), "KuznyechikCFBPKCS7Padding-Decode")

    assert(data, cyptdeStr, "KuznyechikCFBPKCS7Padding")
}

func Test_SkipjackCFBPKCS7Padding(t *testing.T) {
    assert := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    data := "test-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-pass"
    cypt := FromString(data).
        SetKey("dfertf12df").
        SetIv("jifu87uj").
        Skipjack().
        CFB().
        PKCS7Padding().
        Encrypt()
    cyptStr := cypt.ToBase64String()

    assertError(cypt.Error(), "SkipjackCFBPKCS7Padding-Encode")

    cyptde := FromBase64String(cyptStr).
        SetKey("dfertf12df").
        SetIv("jifu87uj").
        Skipjack().
        CFB().
        PKCS7Padding().
        Decrypt()
    cyptdeStr := cyptde.ToString()

    assertError(cyptde.Error(), "SkipjackCFBPKCS7Padding-Decode")

    assert(data, cyptdeStr, "SkipjackCFBPKCS7Padding")
}

func Test_SerpentCFBPKCS7Padding(t *testing.T) {
    assert := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    data := "test-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-pass"
    cypt := FromString(data).
        SetKey("dfertf12dfertf12").
        SetIv("jifu87ujjifu87uj").
        Serpent().
        CFB().
        PKCS7Padding().
        Encrypt()
    cyptStr := cypt.ToBase64String()

    assertError(cypt.Error(), "SerpentCFBPKCS7Padding-Encode")

    cyptde := FromBase64String(cyptStr).
        SetKey("dfertf12dfertf12").
        SetIv("jifu87ujjifu87uj").
        Serpent().
        CFB().
        PKCS7Padding().
        Decrypt()
    cyptdeStr := cyptde.ToString()

    assertError(cyptde.Error(), "SerpentCFBPKCS7Padding-Decode")

    assert(data, cyptdeStr, "SerpentCFBPKCS7Padding")
}

func Test_OnError(t *testing.T) {
    assertBool := cryptobin_test.AssertBoolT(t)
    assertEmpty := cryptobin_test.AssertEmptyT(t)

    data := "test-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-pass"
    cyptStr := FromString(data).
        SetKey("dfertf12dfertf123").
        SetIv("jifu87ujjifu87uj").
        Serpent().
        CFB().
        PKCS7Padding().
        OnError(func(errs []error) {
            assertBool(len(errs) > 0, "OnError-Errs Encrypt")
        }).
        Encrypt().
        ToBase64String()
    assertEmpty(cyptStr, "OnError-Encrypt Empty")

    cyptdeStr := FromBase64String(cyptStr).
        SetKey("dfertf12dfertf123").
        SetIv("jifu87ujjifu87uj").
        Serpent().
        CFB().
        PKCS7Padding().
        OnError(func(errs []error) {
            assertBool(len(errs) > 0, "OnError-Errs Decrypt")
        }).
        Decrypt().
        ToString()

    assertEmpty(cyptdeStr, "OnError-Decrypt Empty")
}

func Test_AesOCBPKCS7Padding(t *testing.T) {
    assert := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    data := "test-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-pass"
    cypt := New().
        FromString(data).
        SetKey("dfertf12dfertf12").
        SetIv("dfertf12dfer").
        Aes().
        OCB().
        PKCS7Padding().
        Encrypt()
    cyptStr := cypt.ToBase64String()

    assertError(cypt.Error(), "AesOCBPKCS7Padding-Encode")

    cyptde := New().
        FromBase64String(cyptStr).
        SetKey("dfertf12dfertf12").
        SetIv("dfertf12dfer").
        Aes().
        OCB().
        PKCS7Padding().
        Decrypt()
    cyptdeStr := cyptde.ToString()

    assertError(cyptde.Error(), "AesOCBPKCS7Padding-Decode")

    assert(data, cyptdeStr, "AesOCBPKCS7Padding")
}

func Test_AesEAXPKCS7Padding(t *testing.T) {
    assert := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    data := "test-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-pass"
    cypt := FromString(data).
        SetKey("dfertf12dfertf12").
        SetIv("dfertf12dfertf").
        Aes().
        EAX().
        PKCS7Padding().
        Encrypt()
    cyptStr := cypt.ToBase64String()

    assertError(cypt.Error(), "Test_AesEAXPKCS7Padding-Encode")

    cyptde := FromBase64String(cyptStr).
        SetKey("dfertf12dfertf12").
        SetIv("dfertf12dfertf").
        Aes().
        EAX().
        PKCS7Padding().
        Decrypt()
    cyptdeStr := cyptde.ToString()

    assertError(cyptde.Error(), "Test_AesEAXPKCS7Padding-Decode")

    assert(data, cyptdeStr, "Test_AesEAXPKCS7Padding")
}

func Test_AesCCMPKCS7Padding(t *testing.T) {
    assert := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    data := "test-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-pass"
    cypt := FromString(data).
        SetKey("dfertf12dfertf12").
        SetIv("dfertf12dfe").
        Aes().
        CCM().
        PKCS7Padding().
        Encrypt()
    cyptStr := cypt.ToBase64String()

    assertError(cypt.Error(), "AesCCMPKCS7Padding-Encode")

    cyptde := FromBase64String(cyptStr).
        SetKey("dfertf12dfertf12").
        SetIv("dfertf12dfe").
        Aes().
        CCM().
        PKCS7Padding().
        Decrypt()
    cyptdeStr := cyptde.ToString()

    assertError(cyptde.Error(), "AesCCMPKCS7Padding-Decode")

    assert(data, cyptdeStr, "AesCCMPKCS7Padding")
}

func Test_AesOCFB(t *testing.T) {
    assert := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    data := "test-pass"
    cypt := FromString(data).
        SetKey("dfertf12dfertf12").
        Aes().
        OCFB(true).
        Encrypt()
    cyptStr := cypt.ToBase64String()

    assertError(cypt.Error(), "AesOCFB-Encode")

    cyptde := FromBase64String(cyptStr).
        SetKey("dfertf12dfertf12").
        Aes().
        OCFB(true).
        Decrypt()
    cyptdeStr := cyptde.ToString()

    assertError(cyptde.Error(), "AesOCFB-Decode")

    assert(data, cyptdeStr, "AesOCFB")
}

func Test_AesOCFBFalse(t *testing.T) {
    assert := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    data := "test-pass12trtrt7yh"
    cypt := FromString(data).
        SetKey("dfertf12dfertf12dfertf12").
        Aes().
        OCFB(false).
        Encrypt()
    cyptStr := cypt.ToBase64String()

    assertError(cypt.Error(), "AesOCFBFalse-Encode")

    cyptde := FromBase64String(cyptStr).
        SetKey("dfertf12dfertf12dfertf12").
        Aes().
        OCFB(false).
        Decrypt()
    cyptdeStr := cyptde.ToString()

    assertError(cyptde.Error(), "AesOCFBFalse-Decode")

    assert(data, cyptdeStr, "AesOCFBFalse")
}

func Test_AesCBCISO10126Padding(t *testing.T) {
    assert := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    data := "test-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-pass"
    cypt := FromString(data).
        SetKey("dfertf12dfertf12").
        SetIv("dfertf12dfertf12").
        Aes().
        CBC().
        ISO10126Padding().
        Encrypt()
    cyptStr := cypt.ToBase64String()

    assertError(cypt.Error(), "AesCBCISO10126Padding-Encode")

    cyptde := FromBase64String(cyptStr).
        SetKey("dfertf12dfertf12").
        SetIv("dfertf12dfertf12").
        Aes().
        CBC().
        ISO10126Padding().
        Decrypt()
    cyptdeStr := cyptde.ToString()

    assertError(cyptde.Error(), "AesCBCISO10126Padding-Decode")

    assert(data, cyptdeStr, "AesCBCISO10126Padding-res")
}

func Test_TripleDESCBC_Check(t *testing.T) {
    assert := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    oldData := "test-pass"

    iv := "iokjiuji"
    key := "asdferkijuhjkiloiokjiuji"

    cryptoData := "RnkirpLEmCdRaw3dF7KyQw=="

    cyptde := FromBase64String(cryptoData).
        SetKey(key).
        SetIv(iv).
        TripleDes().
        CBC().
        PKCS7Padding().
        Decrypt()
    cyptdeStr := cyptde.ToString()

    assertError(cyptde.Error(), "TripleDESCBC_Check-Decode")

    assert(oldData, cyptdeStr, "TripleDESCBC_Check-res")
}

func Test_TwoDesCBC_Check(t *testing.T) {
    assert := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    oldData := "test-pass"

    iv := "iokjiuji"
    key := "asdferkijuhjkilo"

    cryptoData := "xTHCFwYOhSUxmfDqn4zntQ=="

    cyptde := FromBase64String(cryptoData).
        SetKey(key).
        SetIv(iv).
        TwoDes().
        CBC().
        PKCS7Padding().
        Decrypt()
    cyptdeStr := cyptde.ToString()

    assertError(cyptde.Error(), "TwoDesCBC_Check-Decode")

    assert(oldData, cyptdeStr, "TwoDesCBC-res")
}

func Test_RC5PKCS7Padding(t *testing.T) {
    assert := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    data := "test-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-pass"
    cypt := FromString(data).
        SetKey("dfertf12dfertf12").
        SetIv("dfertf12").
        RC5(32, 12).
        CBC().
        PKCS7Padding().
        Encrypt()
    cyptStr := cypt.ToBase64String()

    assertError(cypt.Error(), "RC5PKCS7Padding-Encode")

    cyptde := FromBase64String(cyptStr).
        SetKey("dfertf12dfertf12").
        SetIv("dfertf12").
        RC5(32, 12).
        CBC().
        PKCS7Padding().
        Decrypt()
    cyptdeStr := cyptde.ToString()

    assertError(cyptde.Error(), "RC5PKCS7Padding-Decode")

    assert(data, cyptdeStr, "RC5PKCS7Padding-res")
}

func Test_RC5PKCS7Padding_Check(t *testing.T) {
    assert := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    oldData := "测试数据"

    key := "dfguijki"

    cryptoData := "d7qx+SQCzI2cKkDTO/oCkQ=="

    cyptde := FromBase64String(cryptoData).
        SetKey(key).
        RC5(32, 12).
        ECB().
        PKCS7Padding().
        Decrypt()
    cyptdeStr := cyptde.ToString()

    assertError(cyptde.Error(), "RC5PKCS7Padding_Check-Decode")

    assert(oldData, cyptdeStr, "RC5PKCS7Padding_Check-res")
}

func Test_RC6PKCS7Padding(t *testing.T) {
    assert := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    data := "test-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-pass"
    cypt := FromString(data).
        SetKey("dfertf12dfertf12").
        SetIv("dfertf12dfertf12").
        RC6().
        CBC().
        PKCS7Padding().
        Encrypt()
    cyptStr := cypt.ToBase64String()

    assertError(cypt.Error(), "RC6PKCS7Padding-Encode")

    cyptde := FromBase64String(cyptStr).
        SetKey("dfertf12dfertf12").
        SetIv("dfertf12dfertf12").
        RC6().
        CBC().
        PKCS7Padding().
        Decrypt()
    cyptdeStr := cyptde.ToString()

    assertError(cyptde.Error(), "RC6PKCS7Padding-Decode")

    assert(data, cyptdeStr, "RC6PKCS7Padding-res")
}

func Test_RC6PKCS7Padding_Check(t *testing.T) {
    assert := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    oldData := "ckijhslfg"

    key := "jiko9jnmjiko9jnm"

    cryptoData := "aQCJ4wRSJiSbZve8aqT+pw=="

    cyptde := FromBase64String(cryptoData).
        SetKey(key).
        RC6().
        ECB().
        PKCS7Padding().
        Decrypt()
    cyptdeStr := cyptde.ToString()

    assertError(cyptde.Error(), "RC6PKCS7Padding_Check-Decode")

    assert(oldData, cyptdeStr, "RC6PKCS7Padding_Check-res")
}

func Test_Loki97PKCS7Padding(t *testing.T) {
    assert := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    data := "test-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-pass"
    cypt := FromString(data).
        SetKey("dfertf12dfertf12").
        SetIv("dfertf12dfertf12").
        Loki97().
        CBC().
        PKCS7Padding().
        Encrypt()
    cyptStr := cypt.ToBase64String()

    assertError(cypt.Error(), "Loki97PKCS7Padding-Encode")

    cyptde := FromBase64String(cyptStr).
        SetKey("dfertf12dfertf12").
        SetIv("dfertf12dfertf12").
        Loki97().
        CBC().
        PKCS7Padding().
        Decrypt()
    cyptdeStr := cyptde.ToString()

    assertError(cyptde.Error(), "Loki97PKCS7Padding-Decode")

    assert(data, cyptdeStr, "Loki97PKCS7Padding-res")
}

func Test_AesNCFB(t *testing.T) {
    assert := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    data := "test-pass"
    cypt := FromString(data).
        SetKey("dfertf12dfertf12").
        SetIv("dfertf12ghnjhyuj").
        Aes().
        NCFB().
        Encrypt()
    cyptStr := cypt.ToBase64String()

    assertError(cypt.Error(), "AesNCFB-Encode")

    cyptde := FromBase64String(cyptStr).
        SetKey("dfertf12dfertf12").
        SetIv("dfertf12ghnjhyuj").
        Aes().
        NCFB().
        Decrypt()
    cyptdeStr := cyptde.ToString()

    assertError(cyptde.Error(), "AesNCFB-Decode")

    assert(data, cyptdeStr, "AesNCFB")
}

func Test_AesNOFB(t *testing.T) {
    assert := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    data := "test-pass"
    cypt := FromString(data).
        SetKey("dfertf12dfertf12").
        SetIv("dfertf12ghnjhyuj").
        Aes().
        NOFB().
        Encrypt()
    cyptStr := cypt.ToBase64String()

    assertError(cypt.Error(), "AesNOFB-Encode")

    cyptde := FromBase64String(cyptStr).
        SetKey("dfertf12dfertf12").
        SetIv("dfertf12ghnjhyuj").
        Aes().
        NOFB().
        Decrypt()
    cyptdeStr := cyptde.ToString()

    assertError(cyptde.Error(), "AesNOFB-Decode")

    assert(data, cyptdeStr, "AesNOFB")
}

func Test_SaferplusPKCS7Padding(t *testing.T) {
    assert := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    data := "test-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-pass"
    cypt := FromString(data).
        SetKey("dfertf12dfertf12").
        SetIv("dfertf12").
        Saferplus().
        CBC().
        PKCS7Padding().
        Encrypt()
    cyptStr := cypt.ToBase64String()

    assertError(cypt.Error(), "SaferplusPKCS7Padding-Encode")

    cyptde := FromBase64String(cyptStr).
        SetKey("dfertf12dfertf12").
        SetIv("dfertf12").
        Saferplus().
        CBC().
        PKCS7Padding().
        Decrypt()
    cyptdeStr := cyptde.ToString()

    assertError(cyptde.Error(), "SaferplusPKCS7Padding-Decode")

    assert(data, cyptdeStr, "SaferplusPKCS7Padding-res")
}

func Test_MarsPKCS7Padding(t *testing.T) {
    assert := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    data := "test-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-pass"
    cypt := FromString(data).
        SetKey("dfertf12dfertf12").
        SetIv("dfertf12dfertf12").
        Mars().
        CBC().
        PKCS7Padding().
        Encrypt()
    cyptStr := cypt.ToBase64String()

    assertError(cypt.Error(), "MarsPKCS7Padding-Encode")

    cyptde := FromBase64String(cyptStr).
        SetKey("dfertf12dfertf12").
        SetIv("dfertf12dfertf12").
        Mars().
        CBC().
        PKCS7Padding().
        Decrypt()
    cyptdeStr := cyptde.ToString()

    assertError(cyptde.Error(), "MarsPKCS7Padding-Decode")

    assert(data, cyptdeStr, "MarsPKCS7Padding-res")
}

func Test_Mars2PKCS7Padding(t *testing.T) {
    assert := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    data := "test-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-pass"
    cypt := FromString(data).
        SetKey("dfertf12dfertf12").
        SetIv("dfertf12dfertf12").
        Mars2().
        CBC().
        PKCS7Padding().
        Encrypt()
    cyptStr := cypt.ToBase64String()

    assertError(cypt.Error(), "Mars2PKCS7Padding-Encode")

    cyptde := FromBase64String(cyptStr).
        SetKey("dfertf12dfertf12").
        SetIv("dfertf12dfertf12").
        Mars2().
        CBC().
        PKCS7Padding().
        Decrypt()
    cyptdeStr := cyptde.ToString()

    assertError(cyptde.Error(), "Mars2PKCS7Padding-Decode")

    assert(data, cyptdeStr, "Mars2PKCS7Padding-res")
}

func Test_WakeNoPadding(t *testing.T) {
    assert := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    data := "test-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-pass"
    cypt := FromString(data).
        SetKey("dfertf12dfertf12").
        Wake().
        ECB().
        NoPadding().
        Encrypt()
    cyptStr := cypt.ToBase64String()

    assertError(cypt.Error(), "WakeNoPadding-Encode")

    cyptde := FromBase64String(cyptStr).
        SetKey("dfertf12dfertf12").
        Wake().
        ECB().
        NoPadding().
        Decrypt()
    cyptdeStr := cyptde.ToString()

    assertError(cyptde.Error(), "WakeNoPadding-Decode")

    assert(data, cyptdeStr, "WakeNoPadding-res")
}

func Test_Enigma(t *testing.T) {
    assert := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    data := "test-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-pass"
    cypt := FromString(data).
        SetKey("dfertf12dfert").
        Enigma().
        Encrypt()
    cyptStr := cypt.ToBase64String()

    assertError(cypt.Error(), "EnigmaNoPadding-Encode")

    cyptde := FromBase64String(cyptStr).
        SetKey("dfertf12dfert").
        Enigma().
        Decrypt()
    cyptdeStr := cyptde.ToString()

    assertError(cyptde.Error(), "EnigmaNoPadding-Decode")

    assert(data, cyptdeStr, "EnigmaNoPadding-res")
}

func Test_Cast256PKCS7Padding(t *testing.T) {
    assert := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    data := "test-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-pass"
    cypt := FromString(data).
        SetKey("dfertf12dfertf12dfertf12dfertf12").
        SetIv("dfertf12dfertf12").
        Cast256().
        CBC().
        PKCS7Padding().
        Encrypt()
    cyptStr := cypt.ToBase64String()

    assertError(cypt.Error(), "Cast256PKCS7Padding-Encode")

    cyptde := FromBase64String(cyptStr).
        SetKey("dfertf12dfertf12dfertf12dfertf12").
        SetIv("dfertf12dfertf12").
        Cast256().
        CBC().
        PKCS7Padding().
        Decrypt()
    cyptdeStr := cyptde.ToString()

    assertError(cyptde.Error(), "Cast256PKCS7Padding-Decode")

    assert(data, cyptdeStr, "Cast256PKCS7Padding-res")
}

func Test_HightPKCS7Padding(t *testing.T) {
    assert := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    data := "test-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-pass"
    cypt := FromString(data).
        SetKey("dfertf12dfertf12").
        SetIv("dfertf12").
        Hight().
        CBC().
        PKCS7Padding().
        Encrypt()
    cyptStr := cypt.ToBase64String()

    assertError(cypt.Error(), "HightPKCS7Padding-Encode")

    cyptde := FromBase64String(cyptStr).
        SetKey("dfertf12dfertf12").
        SetIv("dfertf12").
        Hight().
        CBC().
        PKCS7Padding().
        Decrypt()
    cyptdeStr := cyptde.ToString()

    assertError(cyptde.Error(), "HightPKCS7Padding-Decode")

    assert(data, cyptdeStr, "HightPKCS7Padding-res")
}

func Test_LeaPKCS7Padding(t *testing.T) {
    assert := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    data := "test-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-pass"
    cypt := FromString(data).
        SetKey("dfertf12dfertf12dfertf12dfertf12").
        SetIv("dfertf12dfertf12").
        Lea().
        CBC().
        PKCS7Padding().
        Encrypt()
    cyptStr := cypt.ToBase64String()

    assertError(cypt.Error(), "LeaPKCS7Padding-Encode")

    cyptde := FromBase64String(cyptStr).
        SetKey("dfertf12dfertf12dfertf12dfertf12").
        SetIv("dfertf12dfertf12").
        Lea().
        CBC().
        PKCS7Padding().
        Decrypt()
    cyptdeStr := cyptde.ToString()

    assertError(cyptde.Error(), "LeaPKCS7Padding-Decode")

    assert(data, cyptdeStr, "LeaPKCS7Padding-res")
}

func Test_Panama(t *testing.T) {
    assert := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    data := "test-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-pass"
    cypt := FromString(data).
        SetKey("dfertf12dfertf12dfertf12dfertf12").
        Panama().
        Encrypt()
    cyptStr := cypt.ToBase64String()

    assertError(cypt.Error(), "Panama-Encode")

    cyptde := FromBase64String(cyptStr).
        SetKey("dfertf12dfertf12dfertf12dfertf12").
        Panama().
        Decrypt()
    cyptdeStr := cyptde.ToString()

    assertError(cyptde.Error(), "Panama-Decode")

    assert(data, cyptdeStr, "Panama-res")
}

func Test_Square(t *testing.T) {
    assert := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    data := "test-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-pass"
    cypt := FromString(data).
        SetKey("dfertf12dfertf12").
        SetIv("dertf1d2fgtyf12d").
        Square().
        CBC().
        PKCS7Padding().
        Encrypt()
    cyptStr := cypt.ToBase64String()

    assertError(cypt.Error(), "Square-Encode")

    cyptde := FromBase64String(cyptStr).
        SetKey("dfertf12dfertf12").
        SetIv("dertf1d2fgtyf12d").
        Square().
        CBC().
        PKCS7Padding().
        Decrypt()
    cyptdeStr := cyptde.ToString()

    assertError(cyptde.Error(), "Square-Decode")

    assert(cyptdeStr, data, "Square-res")
}

func Test_Magenta(t *testing.T) {
    assert := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    data := "test-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-pass"
    cypt := FromString(data).
        SetKey("dfertf12dfertf12dfertf12dfertf12").
        SetIv("dfertf1d2fgtyf12").
        Magenta().
        CBC().
        PKCS7Padding().
        Encrypt()
    cyptStr := cypt.ToBase64String()

    assertError(cypt.Error(), "Magenta-Encode")

    cyptde := FromBase64String(cyptStr).
        SetKey("dfertf12dfertf12dfertf12dfertf12").
        SetIv("dfertf1d2fgtyf12").
        Magenta().
        CBC().
        PKCS7Padding().
        Decrypt()
    cyptdeStr := cyptde.ToString()

    assertError(cyptde.Error(), "Magenta-Decode")

    assert(cyptdeStr, data, "Magenta-res")
}

func Test_Kasumi(t *testing.T) {
    assert := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    data := "test-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-pass"
    cypt := FromString(data).
        SetKey("dfertf1d2fgtyf35").
        SetIv("dfrgt6yh").
        Kasumi().
        CBC().
        PKCS7Padding().
        Encrypt()
    cyptStr := cypt.ToBase64String()

    assertError(cypt.Error(), "Kasumi-Encode")

    cyptde := FromBase64String(cyptStr).
        SetKey("dfertf1d2fgtyf35").
        SetIv("dfrgt6yh").
        Kasumi().
        CBC().
        PKCS7Padding().
        Decrypt()
    cyptdeStr := cyptde.ToString()

    assertError(cyptde.Error(), "Kasumi-Decode")

    assert(cyptdeStr, data, "Kasumi-res")
}

func Test_E2(t *testing.T) {
    assert := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    data := "test-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-pass"
    cypt := FromString(data).
        SetKey("dfertf1d2fgtyf35").
        SetIv("dfertf1d2fgtyfdf").
        E2().
        CBC().
        PKCS7Padding().
        Encrypt()
    cyptStr := cypt.ToBase64String()

    assertError(cypt.Error(), "E2-Encode")

    cyptde := FromBase64String(cyptStr).
        SetKey("dfertf1d2fgtyf35").
        SetIv("dfertf1d2fgtyfdf").
        E2().
        CBC().
        PKCS7Padding().
        Decrypt()
    cyptdeStr := cyptde.ToString()

    assertError(cyptde.Error(), "E2-Decode")

    assert(cyptdeStr, data, "E2-res")
}

func Test_Crypton1(t *testing.T) {
    assert := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    data := "test-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-pass"
    cypt := FromString(data).
        SetKey("dfertf1d2fgtyf35").
        SetIv("dfertf1d2fgtyfdf").
        Crypton1().
        CBC().
        PKCS7Padding().
        Encrypt()
    cyptStr := cypt.ToBase64String()

    assertError(cypt.Error(), "Crypton1-Encode")

    cyptde := FromBase64String(cyptStr).
        SetKey("dfertf1d2fgtyf35").
        SetIv("dfertf1d2fgtyfdf").
        Crypton1().
        CBC().
        PKCS7Padding().
        Decrypt()
    cyptdeStr := cyptde.ToString()

    assertError(cyptde.Error(), "Crypton1-Decode")

    assert(cyptdeStr, data, "Crypton1-res")
}

func Test_Clefia(t *testing.T) {
    assert := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    data := "test-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-pass"
    cypt := FromString(data).
        SetKey("dfertf1d2fgtyf35").
        SetIv("dfertf1d2fgtyfdf").
        Clefia().
        CBC().
        PKCS7Padding().
        Encrypt()
    cyptStr := cypt.ToBase64String()

    assertError(cypt.Error(), "Clefia-Encode")

    cyptde := FromBase64String(cyptStr).
        SetKey("dfertf1d2fgtyf35").
        SetIv("dfertf1d2fgtyfdf").
        Clefia().
        CBC().
        PKCS7Padding().
        Decrypt()
    cyptdeStr := cyptde.ToString()

    assertError(cyptde.Error(), "Clefia-Decode")

    assert(cyptdeStr, data, "Clefia-res")
}

func Test_Safer(t *testing.T) {
    assert := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    data := "test-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-pass"
    cypt := FromString(data).
        SetKey("dfertf1d2fgtyf35").
        SetIv("dfertf1d").
        Safer("SK", 6).
        CBC().
        PKCS7Padding().
        Encrypt()
    cyptStr := cypt.ToBase64String()

    assertError(cypt.Error(), "Safer-Encode")

    cyptde := FromBase64String(cyptStr).
        SetKey("dfertf1d2fgtyf35").
        SetIv("dfertf1d").
        Safer("SK", 6).
        CBC().
        PKCS7Padding().
        Decrypt()
    cyptdeStr := cyptde.ToString()

    assertError(cyptde.Error(), "Safer-Decode")

    assert(cyptdeStr, data, "Safer-res")
}

func Test_Noekeon(t *testing.T) {
    assert := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    data := "test-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-pass"
    cypt := FromString(data).
        SetKey("dfertf1d2fgtyf35").
        SetIv("dfertf1d2fgtyfdf").
        Noekeon().
        CBC().
        PKCS7Padding().
        Encrypt()
    cyptStr := cypt.ToBase64String()

    assertError(cypt.Error(), "Noekeon-Encode")

    cyptde := FromBase64String(cyptStr).
        SetKey("dfertf1d2fgtyf35").
        SetIv("dfertf1d2fgtyfdf").
        Noekeon().
        CBC().
        PKCS7Padding().
        Decrypt()
    cyptdeStr := cyptde.ToString()

    assertError(cyptde.Error(), "Noekeon-Decode")

    assert(cyptdeStr, data, "Noekeon-res")
}

func Test_Multi2(t *testing.T) {
    assert := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    data := "test-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-pass"
    cypt := FromString(data).
        SetKey("dfertf1d2fgtyf35dfertf1d2fgtyf35fvcdhjnk").
        SetIv("dfertf1d").
        Multi2(128).
        CBC().
        PKCS7Padding().
        Encrypt()
    cyptStr := cypt.ToBase64String()

    assertError(cypt.Error(), "Multi2-Encode")

    cyptde := FromBase64String(cyptStr).
        SetKey("dfertf1d2fgtyf35dfertf1d2fgtyf35fvcdhjnk").
        SetIv("dfertf1d").
        Multi2(128).
        CBC().
        PKCS7Padding().
        Decrypt()
    cyptdeStr := cyptde.ToString()

    assertError(cyptde.Error(), "Multi2-Decode")

    assert(cyptdeStr, data, "Multi2-res")
}

func Test_Kseed(t *testing.T) {
    assert := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    data := "test-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-pass"
    cypt := FromString(data).
        SetKey("dfertf1d2fgtyf35").
        SetIv("dfertf1d2fgtyfdf").
        Kseed().
        CBC().
        PKCS7Padding().
        Encrypt()
    cyptStr := cypt.ToBase64String()

    assertError(cypt.Error(), "Kseed-Encode")

    cyptde := FromBase64String(cyptStr).
        SetKey("dfertf1d2fgtyf35").
        SetIv("dfertf1d2fgtyfdf").
        Kseed().
        CBC().
        PKCS7Padding().
        Decrypt()
    cyptdeStr := cyptde.ToString()

    assertError(cyptde.Error(), "Kseed-Decode")

    assert(cyptdeStr, data, "Kseed-res")
}

func Test_Khazad(t *testing.T) {
    assert := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    data := "test-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-pass"
    cypt := FromString(data).
        SetKey("dfertf1d2fgtyf35").
        SetIv("dfertf1d").
        Khazad().
        CBC().
        PKCS7Padding().
        Encrypt()
    cyptStr := cypt.ToBase64String()

    assertError(cypt.Error(), "Khazad-Encode")

    cyptde := FromBase64String(cyptStr).
        SetKey("dfertf1d2fgtyf35").
        SetIv("dfertf1d").
        Khazad().
        CBC().
        PKCS7Padding().
        Decrypt()
    cyptdeStr := cyptde.ToString()

    assertError(cyptde.Error(), "Khazad-Decode")

    assert(cyptdeStr, data, "Khazad-res")
}

func Test_Anubis(t *testing.T) {
    assert := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    data := "test-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-pass"
    cypt := FromString(data).
        SetKey("dfertf1d2fgtyf35").
        SetIv("dfertf1dfvb5gtyh").
        Anubis().
        CBC().
        PKCS7Padding().
        Encrypt()
    cyptStr := cypt.ToBase64String()

    assertError(cypt.Error(), "Anubis-Encode")

    cyptde := FromBase64String(cyptStr).
        SetKey("dfertf1d2fgtyf35").
        SetIv("dfertf1dfvb5gtyh").
        Anubis().
        CBC().
        PKCS7Padding().
        Decrypt()
    cyptdeStr := cyptde.ToString()

    assertError(cyptde.Error(), "Anubis-Decode")

    assert(cyptdeStr, data, "Anubis-res")
}

func Test_AesBC(t *testing.T) {
    assert := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    data := "test-pass"
    cypt := FromString(data).
        SetKey("dfertf12dfertf12").
        SetIv("dfertf12ghnjhyuj").
        Aes().
        BC().
        PKCS7Padding().
        Encrypt()
    cyptStr := cypt.ToBase64String()

    assertError(cypt.Error(), "AesBC-Encode")

    cyptde := FromBase64String(cyptStr).
        SetKey("dfertf12dfertf12").
        SetIv("dfertf12ghnjhyuj").
        Aes().
        BC().
        PKCS7Padding().
        Decrypt()
    cyptdeStr := cyptde.ToString()

    assertError(cyptde.Error(), "AesBC-Decode")

    assert(data, cyptdeStr, "AesBC")
}

func Test_AesHCTR(t *testing.T) {
    assert := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    tweak := []byte("kkinjkijeel2pass")
    hkey := []byte("11injkijkol22plo")

    data := "test-pass"
    cypt := FromString(data).
        SetKey("dfertf12dfertf12").
        SetIv("dfertf12ghnjhyuj").
        Aes().
        HCTR(tweak, hkey).
        PKCS7Padding().
        Encrypt()
    cyptStr := cypt.ToBase64String()

    assertError(cypt.Error(), "AesHCTR-Encode")

    cyptde := FromBase64String(cyptStr).
        SetKey("dfertf12dfertf12").
        SetIv("dfertf12ghnjhyuj").
        Aes().
        HCTR(tweak, hkey).
        PKCS7Padding().
        Decrypt()
    cyptdeStr := cyptde.ToString()

    assertError(cyptde.Error(), "AesHCTR-Decode")

    assert(data, cyptdeStr, "AesHCTR")
}

func Test_PresentPKCS7Padding(t *testing.T) {
    assert := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    data := "test-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-pass"
    cypt := FromString(data).
        SetKey("dfertf12dfertf12").
        SetIv("dfertf12").
        Present().
        CBC().
        PKCS7Padding().
        Encrypt()
    cyptStr := cypt.ToBase64String()

    assertError(cypt.Error(), "PresentPKCS7Padding-Encode")

    cyptde := FromBase64String(cyptStr).
        SetKey("dfertf12dfertf12").
        SetIv("dfertf12").
        Present().
        CBC().
        PKCS7Padding().
        Decrypt()
    cyptdeStr := cyptde.ToString()

    assertError(cyptde.Error(), "PresentPKCS7Padding-Decode")

    assert(data, cyptdeStr, "PresentPKCS7Padding-res")
}

func Test_Trivium(t *testing.T) {
    assert := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    data := "test-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-pass"
    cypt := FromString(data).
        SetKey("dfyytf1256").
        SetIv("dfertf1256").
        Trivium().
        Encrypt()
    cyptStr := cypt.ToBase64String()

    assertError(cypt.Error(), "Trivium-Encode")

    cyptde := FromBase64String(cyptStr).
        SetKey("dfyytf1256").
        SetIv("dfertf1256").
        Trivium().
        Decrypt()
    cyptdeStr := cyptde.ToString()

    assertError(cyptde.Error(), "Trivium-Decode")

    assert(data, cyptdeStr, "Trivium-res")
}

func Test_Rijndael128PKCS7Padding(t *testing.T) {
    assert := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    data := "test-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-pass"
    cypt := FromString(data).
        SetKey("dfertf12dfertf12").
        SetIv("dfertf12dfertf12").
        Rijndael128().
        CBC().
        PKCS7Padding().
        Encrypt()
    cyptStr := cypt.ToBase64String()

    assertError(cypt.Error(), "Rijndael128PKCS7Padding-Encode")

    cyptde := FromBase64String(cyptStr).
        SetKey("dfertf12dfertf12").
        SetIv("dfertf12dfertf12").
        Rijndael128().
        CBC().
        PKCS7Padding().
        Decrypt()
    cyptdeStr := cyptde.ToString()

    assertError(cyptde.Error(), "Rijndael128PKCS7Padding-Decode")

    assert(data, cyptdeStr, "Rijndael128PKCS7Padding-res")
}

func Test_Rijndael192PKCS7Padding(t *testing.T) {
    assert := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    data := "test-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-pass"
    cypt := FromString(data).
        SetKey("dfertf12dfertf12").
        SetIv("dfertf12dfertf12dfertf12").
        Rijndael192().
        CBC().
        PKCS7Padding().
        Encrypt()
    cyptStr := cypt.ToBase64String()

    assertError(cypt.Error(), "Rijndael192PKCS7Padding-Encode")

    cyptde := FromBase64String(cyptStr).
        SetKey("dfertf12dfertf12").
        SetIv("dfertf12dfertf12dfertf12").
        Rijndael192().
        CBC().
        PKCS7Padding().
        Decrypt()
    cyptdeStr := cyptde.ToString()

    assertError(cyptde.Error(), "Rijndael192PKCS7Padding-Decode")

    assert(data, cyptdeStr, "Rijndael192PKCS7Padding-res")
}

func Test_Rijndael256PKCS7Padding(t *testing.T) {
    assert := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    data := "test-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-pass"
    cypt := FromString(data).
        SetKey("dfertf12dfertf12").
        SetIv("dfertf12dfertf12dfertf12dfertf12").
        Rijndael256().
        CBC().
        PKCS7Padding().
        Encrypt()
    cyptStr := cypt.ToBase64String()

    assertError(cypt.Error(), "Rijndael256PKCS7Padding-Encode")

    cyptde := FromBase64String(cyptStr).
        SetKey("dfertf12dfertf12").
        SetIv("dfertf12dfertf12dfertf12dfertf12").
        Rijndael256().
        CBC().
        PKCS7Padding().
        Decrypt()
    cyptdeStr := cyptde.ToString()

    assertError(cyptde.Error(), "Rijndael256PKCS7Padding-Decode")

    assert(data, cyptdeStr, "Rijndael256PKCS7Padding-res")
}

func Test_RijndaelPKCS7Padding(t *testing.T) {
    assert := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    data := "test-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-pass"
    cypt := FromString(data).
        SetKey("dfertf12dfertf12").
        SetIv("dfertf12dfertf12ghnj").
        Rijndael(20).
        CBC().
        PKCS7Padding().
        Encrypt()
    cyptStr := cypt.ToBase64String()

    assertError(cypt.Error(), "RijndaelPKCS7Padding-Encode")

    cyptde := FromBase64String(cyptStr).
        SetKey("dfertf12dfertf12").
        SetIv("dfertf12dfertf12ghnj").
        Rijndael(20).
        CBC().
        PKCS7Padding().
        Decrypt()
    cyptdeStr := cyptde.ToString()

    assertError(cyptde.Error(), "RijndaelPKCS7Padding-Decode")

    assert(data, cyptdeStr, "RijndaelPKCS7Padding-res")
}

func Test_GostGOFBPKCS7Padding(t *testing.T) {
    assert := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    data := "test-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-pass"
    cypt := FromString(data).
        SetKey("dfertf12dfertf12dfertf12dfertf12").
        SetIv("dfertf12").
        Gost("SboxDESDerivedParamSet").
        GOFB().
        PKCS7Padding().
        Encrypt()
    cyptStr := cypt.ToBase64String()

    assertError(cypt.Error(), "Test_GostGOFBPKCS7Padding-Encode")

    cyptde := FromBase64String(cyptStr).
        SetKey("dfertf12dfertf12dfertf12dfertf12").
        SetIv("dfertf12").
        Gost("SboxDESDerivedParamSet").
        GOFB().
        PKCS7Padding().
        Decrypt()
    cyptdeStr := cyptde.ToString()

    assertError(cyptde.Error(), "Test_GostGOFBPKCS7Padding-Decode")

    assert(data, cyptdeStr, "Test_GostGOFBPKCS7Padding-res")
}

func Test_KuznyechikG3413CBCPKCS7Padding(t *testing.T) {
    assert := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    data := "test-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-pass"
    cypt := FromString(data).
        SetKey("dfertf12dfertf12dfertf12dfertf12").
        SetIv("dfertf12dfertf12dfertf12dfertf12").
        Kuznyechik().
        G3413CBC().
        PKCS7Padding().
        Encrypt()
    cyptStr := cypt.ToBase64String()

    assertError(cypt.Error(), "Test_KuznyechikG3413CBCPKCS7Padding-Encode")

    cyptde := FromBase64String(cyptStr).
        SetKey("dfertf12dfertf12dfertf12dfertf12").
        SetIv("dfertf12dfertf12dfertf12dfertf12").
        Kuznyechik().
        G3413CBC().
        PKCS7Padding().
        Decrypt()
    cyptdeStr := cyptde.ToString()

    assertError(cyptde.Error(), "Test_KuznyechikG3413CBCPKCS7Padding-Decode")

    assert(data, cyptdeStr, "Test_KuznyechikG3413CBCPKCS7Padding-res")
}

func Test_KuznyechikG3413CFBPKCS7Padding(t *testing.T) {
    assert := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    data := "test-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-pass"
    cypt := FromString(data).
        SetKey("dfertf12dfertf12dfertf12dfertf12").
        SetIv("dfertf12dfertf12dfertf12dfertf12").
        Kuznyechik().
        G3413CFB().
        PKCS7Padding().
        Encrypt()
    cyptStr := cypt.ToBase64String()

    assertError(cypt.Error(), "Test_KuznyechikG3413CFBPKCS7Padding-Encode")

    cyptde := FromBase64String(cyptStr).
        SetKey("dfertf12dfertf12dfertf12dfertf12").
        SetIv("dfertf12dfertf12dfertf12dfertf12").
        Kuznyechik().
        G3413CFB().
        PKCS7Padding().
        Decrypt()
    cyptdeStr := cyptde.ToString()

    assertError(cyptde.Error(), "Test_KuznyechikG3413CFBPKCS7Padding-Decode")

    assert(data, cyptdeStr, "Test_KuznyechikG3413CFBPKCS7Padding-res")
}

func Test_KuznyechikG3413CFBPKCS7Padding_2(t *testing.T) {
    assert := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    data := "test-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-pass"
    cypt := FromString(data).
        SetKey("dfertf12dfertf12dfertf12dfertf12").
        SetIv("dfertf12dfertf12dfertf12dfertf12").
        Kuznyechik().
        G3413CFB(8).
        PKCS7Padding().
        Encrypt()
    cyptStr := cypt.ToBase64String()

    assertError(cypt.Error(), "Test_KuznyechikG3413CFBPKCS7Padding_2-Encode")

    cyptde := FromBase64String(cyptStr).
        SetKey("dfertf12dfertf12dfertf12dfertf12").
        SetIv("dfertf12dfertf12dfertf12dfertf12").
        Kuznyechik().
        G3413CFB(8).
        PKCS7Padding().
        Decrypt()
    cyptdeStr := cyptde.ToString()

    assertError(cyptde.Error(), "Test_KuznyechikG3413CFBPKCS7Padding_2-Decode")

    assert(data, cyptdeStr, "Test_KuznyechikG3413CFBPKCS7Padding_2-res")
}

func Test_KuznyechikG3413CTRPKCS7Padding(t *testing.T) {
    assert := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    data := "test-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-pass"
    cypt := FromString(data).
        SetKey("dfertf12dfertf12dfertf12dfertf12").
        SetIv("dfertf12").
        Kuznyechik().
        G3413CTR().
        PKCS7Padding().
        Encrypt()
    cyptStr := cypt.ToBase64String()

    assertError(cypt.Error(), "Test_KuznyechikG3413CTRPKCS7Padding-Encode")

    cyptde := FromBase64String(cyptStr).
        SetKey("dfertf12dfertf12dfertf12dfertf12").
        SetIv("dfertf12").
        Kuznyechik().
        G3413CTR().
        PKCS7Padding().
        Decrypt()
    cyptdeStr := cyptde.ToString()

    assertError(cyptde.Error(), "Test_KuznyechikG3413CTRPKCS7Padding-Decode")

    assert(data, cyptdeStr, "Test_KuznyechikG3413CTRPKCS7Padding-res")
}

func Test_KuznyechikG3413CTRPKCS7Padding_2(t *testing.T) {
    assert := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    data := "test-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-pass"
    cypt := FromString(data).
        SetKey("dfertf12dfertf12dfertf12dfertf12").
        SetIv("dfertf12").
        Kuznyechik().
        G3413CTR(8).
        PKCS7Padding().
        Encrypt()
    cyptStr := cypt.ToBase64String()

    assertError(cypt.Error(), "Test_KuznyechikG3413CTRPKCS7Padding_2-Encode")

    cyptde := FromBase64String(cyptStr).
        SetKey("dfertf12dfertf12dfertf12dfertf12").
        SetIv("dfertf12").
        Kuznyechik().
        G3413CTR(8).
        PKCS7Padding().
        Decrypt()
    cyptdeStr := cyptde.ToString()

    assertError(cyptde.Error(), "Test_KuznyechikG3413CTRPKCS7Padding_2-Decode")

    assert(data, cyptdeStr, "Test_KuznyechikG3413CTRPKCS7Padding_2-res")
}

func Test_KuznyechikG3413OFBPKCS7Padding(t *testing.T) {
    assert := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    data := "test-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-pass"
    cypt := FromString(data).
        SetKey("dfertf12dfertf12dfertf12dfertf12").
        SetIv("dfertf12dfer1232dfertf12dfer1232").
        Kuznyechik().
        G3413OFB().
        PKCS7Padding().
        Encrypt()
    cyptStr := cypt.ToBase64String()

    assertError(cypt.Error(), "Test_KuznyechikG3413OFBPKCS7Padding-Encode")

    cyptde := FromBase64String(cyptStr).
        SetKey("dfertf12dfertf12dfertf12dfertf12").
        SetIv("dfertf12dfer1232dfertf12dfer1232").
        Kuznyechik().
        G3413OFB().
        PKCS7Padding().
        Decrypt()
    cyptdeStr := cyptde.ToString()

    assertError(cyptde.Error(), "Test_KuznyechikG3413OFBPKCS7Padding-Decode")

    assert(data, cyptdeStr, "Test_KuznyechikG3413OFBPKCS7Padding-res")
}

func Test_KuznyechikG3413OFBPKCS7Padding_Bad(t *testing.T) {
    empty := cryptobin_test.AssertEmptyT(t)
    notErrorNil := cryptobin_test.AssertNotErrorNilT(t)

    data := "test-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-pass"
    cypt := FromString(data).
        SetKey("dfertf112dfertf12dfertf12dfertf12").
        SetIv("dfertf112dfer1232dfertf12dfer1232").
        Kuznyechik().
        G3413OFB().
        PKCS7Padding().
        Encrypt()
    cyptStr := cypt.ToBase64String()

    notErrorNil(cypt.Error(), "Test_KuznyechikG3413OFBPKCS7Padding_Bad-Encode")
    empty(cyptStr, "Test_KuznyechikG3413OFBPKCS7Padding_Bad-Encode")

    cyptedStr := "4ynA5GUBeN99ly1mXV7ZXGgjY+Y2Gy2ocgjcQkr6fYFIJsBjbF/DtI/y8hxto/MWVYGhU04K0cv7JQAdknoTXX7PdO28Mf5HTh22NDhG6ks6M8csANC66ynjQz5ttF+mOnTqsMfOJ7Ze9r2IhFpX5nA7LfmnRAJ981P92kb/PdGuDEHY/Wg9UIDH/vCSmM5HihASKm0e5bZypq628rXE7W9L5EW2lYrFWq7EuWfjmqUB7uWUTHOkswOSsoMy+dKxudIBx1vQ4lZ6FBzDQxqA62cXSpkTi+zNAo6IbDo2G7zvoEpvsQsSWHtKIQN+q9ANBqYgD0MfGgGnASVc2Qo6MQ=="
    cyptde := FromBase64String(cyptedStr).
        SetKey("dfertf1212dfertf12dfertf12dfertf12").
        SetIv("dfertf1122dfer1232dfertf12dfer1232").
        Kuznyechik().
        G3413OFB().
        PKCS7Padding().
        Decrypt()
    cyptdeStr := cyptde.ToString()

    notErrorNil(cyptde.Error(), "Test_KuznyechikG3413OFBPKCS7Padding_Bad-Decode")
    empty(cyptdeStr, "Test_KuznyechikG3413OFBPKCS7Padding_Bad-Encode")
}

func Test_AESCBC_Check(t *testing.T) {
    eq := cryptobin_test.AssertEqualT(t)
    errChek := cryptobin_test.AssertErrorT(t)

    key := "1234567812345678"
    iv := "2233556612345678"
    msg := "tes-Test_AESCBC-fghdfh345dfsty,;h.hktes-Test_AESCBC-fghdfh345dfsty,;h.hk"

    cyptStr := "sHPZeRkUmU/EcqISg8VgW05t/69AregqYR5rwLgepJRmY/HxbpYTk8hYz1CZSwImlOyrqZ3Jsfodi5wBXRMqfsR+JlFpNYc8xR13tHLK/RI="

    cyptde := FromBase64String(cyptStr).
        SetKey(key).
        SetIv(iv).
        Aes().
        CBC().
        PKCS7Padding().
        Decrypt()
    cyptdeStr := cyptde.ToString()

    errChek(cyptde.Error(), "Test_AESCBC_Check-Decode")
    eq(cyptdeStr, msg, "Test_AESCBC_Check")
}

// 输入数据需手动处理长度，不使用补码方式
func Test_AesWrap(t *testing.T) {
    assert := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    data := "kjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplo"
    cypt := FromString(data).
        SetKey("kkinjkijeel22plo").
        SetIv("dfertf12").
        Aes().
        Wrap().
        Encrypt()
    cyptStr := cypt.ToBase64String()

    assertError(cypt.Error(), "Test_AesWrap-Encode")

    cyptde := FromBase64String(cyptStr).
        SetKey("kkinjkijeel22plo").
        SetIv("dfertf12").
        Aes().
        Wrap().
        Decrypt()
    cyptdeStr := cyptde.ToString()

    assertError(cyptde.Error(), "Test_AesWrap-Decode")

    assert(data, cyptdeStr, "Test_AesWrap")
}

func Test_AesWrapWithNoIV(t *testing.T) {
    assert := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    data := "kjinjkijkolkdplokjinjkijkolkdplokjinjkijkolkdplo"
    cypt := FromString(data).
        SetKey("kkinjkijeel22plo").
        WithIv(nil).
        Aes().
        Wrap().
        Encrypt()
    cyptStr := cypt.ToBase64String()

    assertError(cypt.Error(), "Test_AesWrapWithNoIV-Encode")

    cyptde := FromBase64String(cyptStr).
        SetKey("kkinjkijeel22plo").
        WithIv(nil).
        Aes().
        Wrap().
        Decrypt()
    cyptdeStr := cyptde.ToString()

    assertError(cyptde.Error(), "Test_AesWrapWithNoIV-Decode")

    assert(data, cyptdeStr, "Test_AesWrapWithNoIV")
}

func Test_AesWrap_Check(t *testing.T) {
    assert := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    /* aes key */
    var test_wrap_key = []byte{
        0xee, 0xbc, 0x1f, 0x57, 0x48, 0x7f, 0x51, 0x92, 0x1c, 0x04, 0x65, 0x66,
        0x5f, 0x8a, 0xe6, 0xd1, 0x65, 0x8b, 0xb2, 0x6d, 0xe6, 0xf8, 0xa0, 0x69,
        0xa3, 0x52, 0x02, 0x93, 0xa5, 0x72, 0x07, 0x8f,
    }

    /* Unique initialisation vector */
    var test_wrap_iv = []byte{
        0x99, 0xaa, 0x3e, 0x68, 0xed, 0x81, 0x73, 0xa0, 0xee, 0xd0, 0x66, 0x84,
        0x99, 0xaa, 0x3e, 0x68,
    }

    /* Example plaintext to encrypt */
    var test_wrap_pt = []byte{
        0xad, 0x4f, 0xc9, 0xfc, 0x77, 0x69, 0xc9, 0xea, 0xfc, 0xdf, 0x00, 0xac,
        0x34, 0xec, 0x40, 0xbc, 0x28, 0x3f, 0xa4, 0x5e, 0xd8, 0x99, 0xe4, 0x5d,
        0x5e, 0x7a, 0xc4, 0xe6, 0xca, 0x7b, 0xa5, 0xb7,
    }

    /* Expected ciphertext value */
    var test_wrap_ct = []byte{
        0x97, 0x99, 0x55, 0xca, 0xf6, 0x3e, 0x95, 0x54, 0x39, 0xd6, 0xaf, 0x63, 0xff, 0x2c, 0xe3, 0x96,
        0xf7, 0x0d, 0x2c, 0x9c, 0xc7, 0x43, 0xc0, 0xb6, 0x31, 0x43, 0xb9, 0x20, 0xac, 0x6b, 0xd3, 0x67,
        0xad, 0x01, 0xaf, 0xa7, 0x32, 0x74, 0x26, 0x92,
    }

    cypt := FromBytes(test_wrap_pt).
        WithKey(test_wrap_key).
        WithIv(test_wrap_iv).
        Aes().
        Wrap().
        Encrypt()
    cyptStr := cypt.ToBytes()

    assertError(cypt.Error(), "Test_AesWrap_Check-Encode")
    assert(cyptStr, test_wrap_ct, "Test_AesWrap_Check")
}

func Test_TwinePKCS7Padding(t *testing.T) {
    assert := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    data := "test-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-pass"
    cypt := FromString(data).
        SetKey("dfertf12dfertf12").
        SetIv("dfertf12").
        Twine().
        CBC().
        PKCS7Padding().
        Encrypt()
    cyptStr := cypt.ToBase64String()

    assertError(cypt.Error(), "Test_TwinePKCS7Padding-Encode")

    cyptde := FromBase64String(cyptStr).
        SetKey("dfertf12dfertf12").
        SetIv("dfertf12").
        Twine().
        CBC().
        PKCS7Padding().
        Decrypt()
    cyptdeStr := cyptde.ToString()

    assertError(cyptde.Error(), "Test_TwinePKCS7Padding-Decode")

    assert(cyptdeStr, data, "Test_TwinePKCS7Padding-res")
}

func Test_Misty1PKCS7Padding(t *testing.T) {
    assert := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    data := "test-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-pass"
    cypt := FromString(data).
        SetKey("dfertf12dfertf12").
        SetIv("dfertf12").
        Misty1().
        CBC().
        PKCS7Padding().
        Encrypt()
    cyptStr := cypt.ToBase64String()

    assertError(cypt.Error(), "Test_Misty1PKCS7Padding-Encode")

    cyptde := FromBase64String(cyptStr).
        SetKey("dfertf12dfertf12").
        SetIv("dfertf12").
        Misty1().
        CBC().
        PKCS7Padding().
        Decrypt()
    cyptdeStr := cyptde.ToString()

    assertError(cyptde.Error(), "Test_Misty1PKCS7Padding-Decode")

    assert(cyptdeStr, data, "Test_Misty1PKCS7Padding-res")
}

func Test_Rijndael256NoPadding_Check(t *testing.T) {
    assert := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    uid := "m2Ux0QezsImyNFdtDzYUBWuPf7Ir2AEwJP5l"
    str := "3365616430336134313637303438356562633734666333666136303361343062d9ac29251ae9a36ddb67f8f2ad55eea477239b4d53150feec4a01275d0b1f8b65ffc2f77774eb1203e26050d0f47273b0c35d663da0fa6ddb32b3e0f20cade3204d8f732a74f509c43251c088c523c79c87d02a91cfbc0ca0ff64e8c2e7fb4f6300c584ae84f7de531213747cd3ea50c3f3fa9fc430e784daab2f9777796b0c2"

    data, _ := hex.DecodeString(str)

    keyOld := uid + "xBre2!@348*|AdedFjsDWy01"

    iv := data[:32]
    data = data[32:]

    keyOldMd5 := md5.Sum([]byte(keyOld))
    key := hex.EncodeToString(keyOldMd5[:])

    // iv = 3ead03a41670485ebc74fc3fa603a40b
    // key[:16] = 87de18b595fe6d43
    // hex(data) = d9ac29251ae9a36ddb67f8f2ad55eea477239b4d53150feec4a01275d0b1f8b65ffc2f77774eb1203e26050d0f47273b0c35d663da0fa6ddb32b3e0f20cade3204d8f732a74f509c43251c088c523c79c87d02a91cfbc0ca0ff64e8c2e7fb4f6300c584ae84f7de531213747cd3ea50c3f3fa9fc430e784daab2f9777796b0c2

    cyptde := FromBytes(data).
        SetKey(key[:16]).
        WithIv(iv).
        Rijndael256().
        CBC().
        NoPadding().
        Decrypt()
    cyptdeStr := cyptde.ToString()

    assertError(cyptde.Error(), "Test_Rijndael256NoPadding_Check-Decode")

    // 解密结果: ok ok Request:59ded5eecc800830975a4a1159933981 Hardware:803BB1A8-FFFFA277 License-Type:Demo Multi-Tenant:20 CAL:1000
    check := "6f6b0d0a6f6b0d0a526571756573743a35396465643565656363383030383330393735613461313135393933333938310d0a48617264776172653a38303342423141382d46464646413237370d0a4c6963656e73652d547970653a44656d6f0d0a4d756c74692d54656e616e743a32300d0a43414c3a313030300d0a00000000"

    assert(fmt.Sprintf("%x", cyptdeStr), check, "Test_Rijndael256NoPadding_Check-res")
}

// https://developers.weixin.qq.com/miniprogram/dev/OpenApiDoc/getting_started/api_signature.html
// 微信小程序 api AES256_GCM 加密测试
func Test_Weapp_AES256_GCM_Check(t *testing.T) {
    assert := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    real_plaintext := `{"_n":"o89QaPVsRu1yppIZzvSZc4","_appid":"wxba6223c06417af7b","_timestamp":1635927954,"appid":"wxba6223c06417af7b","openid":"oEWzBfmdLqhFS2mTXCo2E4Y9gJAM","scene":0,"client_ip":"127.0.0.1"}`

    local_sym_key := "otUpngOjU+nVQaWJIC3D/yMLV17RKaP6t4Ot9tbnzLY="
    real_key, _ := base64.StdEncoding.DecodeString(local_sym_key)

    iv := "fmW/zNxXlytUZBgj"
    real_iv, _ := base64.StdEncoding.DecodeString(iv)

    real_aad := "https://api.weixin.qq.com/wxa/getuserriskrank|wxba6223c06417af7b|1635927954|fa05fe1e5bcc79b81ad5ad4b58acf787"

    authtag := "5qeM/2vZv+6KtScN94IpMg=="
    real_authTag, _ := base64.StdEncoding.DecodeString(authtag)

    cypt := FromString(real_plaintext).
        WithKey(real_key).
        WithIv(real_iv).
        Aes().
        GCM([]byte(real_aad)).
        Encrypt()
    cyptStr := cypt.ToBytes()

    assertError(cypt.Error(), "Test_Weapp_AES256_GCM_Check-Decode")

    check := "0IDVdrPtSPF/Oe2CTXCV2vVNPbVJdJlP2WaTMQnoYLh5iCrrSNfQFh25EnStDMf0hLlVNBCZQtf9NaV0m4aRA4AAYIO7oR/Ge+4yY4EmZp5EVPB42xjScgMx5X3D4VdLCfynXIUKUtZHZvk1zmLVE3RauzJgiM1BB1CPmwcENo3MTJ0z8Vfkf5tMv54kOXobDLlV5rfqKdAX7gM/rP82DgZdt9vvZX44ipdbHIjJvw83ZXAFtvftdVw2Qd8="
    real_check, _ := base64.StdEncoding.DecodeString(check)
    real_check = append(real_check, real_authTag...)

    assert(fmt.Sprintf("%x", cyptStr), fmt.Sprintf("%x", real_check), "Test_Weapp_AES256_GCM_Check-res")
}

// 微信小程序 api AES256_GCM 解密测试
func Test_Weapp_AES256_GCM_Check2(t *testing.T) {
    assert := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    ct := `HExs66Ik3el+iM4IpeQ7SMEN934FRLFYOd3EmeaIrpP4EPTHckoco6O+PaoRZRa3lqaPRZT7r52f7LUok6gLxc6cdR8C4vpIIfh4xfLC4L7FNy9GbuMK1hcoi8b7gkWJcwZMkuCFNEDmqn3T49oWzAQOrY4LZnnnykv6oUJotdAsnKvmoJkLK7hRh7M2B1d2UnTnRuoIyarXc5Iojwoghx4BOvnV`
    real_ct, _ := base64.StdEncoding.DecodeString(ct)

    local_sym_key := "otUpngOjU+nVQaWJIC3D/yMLV17RKaP6t4Ot9tbnzLY="
    real_key, _ := base64.StdEncoding.DecodeString(local_sym_key)

    iv := "r2WDQt56rEAmMuoR"
    real_iv, _ := base64.StdEncoding.DecodeString(iv)

    real_aad := "https://api.weixin.qq.com/wxa/getuserriskrank|wxba6223c06417af7b|1635927956|fa05fe1e5bcc79b81ad5ad4b58acf787"

    authtag := "z2BFD8QctKXTuBlhICGOjQ=="
    real_authTag, _ := base64.StdEncoding.DecodeString(authtag)

    real_ct = append(real_ct, real_authTag...)

    cypt := FromBytes(real_ct).
        WithKey(real_key).
        WithIv(real_iv).
        Aes().
        GCM([]byte(real_aad)).
        Decrypt()
    cyptStr := cypt.ToString()

    assertError(cypt.Error(), "Test_Weapp_AES256_GCM_Check-Decode")

    check := `{"_n":"ShYZpqdVgY+yQVAxNSWhYg","_appid":"wxba6223c06417af7b","_timestamp":1635927956,"errcode":0,"errmsg":"getuserriskrank succ","risk_rank":0,"unoin_id":2258658297}`
    assert(cyptStr, check, "Test_Weapp_AES256_GCM_Check-res")
}

// 微信小程序 api SM4_GCM 解密测试
func Test_Weapp_SM4_GCM_Check(t *testing.T) {
    assert := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    ct := `fa8VugXI8UA2ugS646ZvuX0wo4qn0Eua2J9jtwACQXeVys3hP/fZDcZC4eEF9es/z/Zx6GM2piwoHKPmPbwzfNXWc/rUH/USFoKo6OBSiR8bb6QgkzYzYL9KsawMr8X/z6y8o3UzE5w65nfTySQFSpEVplD5S+SwQrLi3I2nUwS5N3SoJYsf8BHVfsYLBI9h1NocLgfjjyPYmeKsQ/t1muVWlV2Z75VbqFhM+ECgHpEvcWPDeUN5ZhZ6C/0=`
    real_ct, _ := base64.StdEncoding.DecodeString(ct)

    local_sym_key := "YXBwaWRkdXNlZm9ydGVzdA=="
    real_key, _ := base64.StdEncoding.DecodeString(local_sym_key)

    iv := "b3sjwc9yvUEGH45l"
    real_iv, _ := base64.StdEncoding.DecodeString(iv)

    real_aad := "https://api.weixin.qq.com/wxa/getuserriskrank|wxba6223c06417af7b|1692932963|fa05fe1e5bcc79b81ad5ad4b58acf787"

    authtag := "cDZY4giOZgf73/CvObhypQ=="
    real_authTag, _ := base64.StdEncoding.DecodeString(authtag)

    real_ct = append(real_ct, real_authTag...)

    cypt := FromBytes(real_ct).
        WithKey(real_key).
        WithIv(real_iv).
        SM4().
        GCM([]byte(real_aad)).
        Decrypt()
    cyptStr := cypt.ToString()

    assertError(cypt.Error(), "Test_Weapp_SM4_GCM_Check-Decode")

    check := `{"appid":"wxba6223c06417af7b","openid":"oEWzBfmdLqhFS2mTXCo2E4Y9gJAM","scene":0,"client_ip":"127.0.0.1","_n":"Mku3TsYcg55vRdTNImb8+w","_appid":"wxba6223c06417af7b","_timestamp":1692932963}`
    assert(cyptStr, check, "Test_Weapp_SM4_GCM_Check-res")
}

func Test_AesGCM(t *testing.T) {
    assert := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    key := "dfertf12dfertf12"
    nonce := "df35tf12df35"
    additional := "123123"

    data := "test-pass"
    cypt := FromString(data).
        SetKey(key).
        SetIv(nonce).
        Aes().
        GCM([]byte(additional)).
        Encrypt()
    cyptStr := cypt.ToBase64String()

    assertError(cypt.Error(), "Test_AesGCM-Encode")

    cyptde := FromBase64String(cyptStr).
        SetKey(key).
        SetIv(nonce).
        Aes().
        GCM([]byte(additional)).
        Decrypt()
    cyptdeStr := cyptde.ToString()

    assertError(cyptde.Error(), "Test_AesGCM-Decode")

    assert(data, cyptdeStr, "Test_AesGCM")
}

func Test_AesGCMWithTagSize(t *testing.T) {
    assert := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    key := "dfertf12dfertf12"
    nonce := "df35tf12df35"
    additional := "123123"

    data := "test-pass"
    cypt := New().
        FromString(data).
        SetKey(key).
        SetIv(nonce).
        Aes().
        GCMWithTagSize(13, []byte(additional)).
        Encrypt()
    cyptStr := cypt.ToBase64String()

    assertError(cypt.Error(), "Test_AesGCMWithTagSize-Encode")

    cyptde := New().
        FromBase64String(cyptStr).
        SetKey(key).
        SetIv(nonce).
        Aes().
        GCMWithTagSize(13, []byte(additional)).
        Decrypt()
    cyptdeStr := cyptde.ToString()

    assertError(cyptde.Error(), "Test_AesGCMWithTagSize-Decode")

    assert(data, cyptdeStr, "Test_AesGCMWithTagSize")
}

func Test_AesCCM(t *testing.T) {
    assert := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    key := "dfertf12dfertf12"
    nonce := "df35tf12df35"
    additional := "123123"

    data := "test-pass"
    cypt := New().
        FromString(data).
        SetKey(key).
        SetIv(nonce).
        Aes().
        CCM([]byte(additional)).
        Encrypt()
    cyptStr := cypt.ToBase64String()

    assertError(cypt.Error(), "Test_AesCCM-Encode")

    cyptde := New().
        FromBase64String(cyptStr).
        SetKey(key).
        SetIv(nonce).
        Aes().
        CCM([]byte(additional)).
        Decrypt()
    cyptdeStr := cyptde.ToString()

    assertError(cyptde.Error(), "Test_AesCCM-Decode")

    assert(data, cyptdeStr, "Test_AesCCM")
}

func Test_AesCCMWithTagSize(t *testing.T) {
    assert := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    key := "dfertf12dfertf12"
    nonce := "df35tf12df35"
    additional := "123123"

    data := "test-pass"
    cypt := FromString(data).
        SetKey(key).
        SetIv(nonce).
        Aes().
        CCMWithTagSize(12, []byte(additional)).
        Encrypt()
    cyptStr := cypt.ToBase64String()

    assertError(cypt.Error(), "Test_AesCCMWithTagSize-Encode")

    cyptde := FromBase64String(cyptStr).
        SetKey(key).
        SetIv(nonce).
        Aes().
        CCMWithTagSize(12, []byte(additional)).
        Decrypt()
    cyptdeStr := cyptde.ToString()

    assertError(cyptde.Error(), "Test_AesCCMWithTagSize-Decode")

    assert(data, cyptdeStr, "Test_AesCCMWithTagSize")
}

func Test_Chacha20(t *testing.T) {
    assert := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    data := "test-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-pass"
    cypt := FromString(data).
        SetKey("dfertf12dfdfertf12dfdfertf12df12").
        SetIv("jifu87ujasef").
        Chacha20().
        Encrypt()
    cyptStr := cypt.ToBase64String()

    assertError(cypt.Error(), "Test_Chacha20-Encode")

    cyptde := FromBase64String(cyptStr).
        SetKey("dfertf12dfdfertf12dfdfertf12df12").
        SetIv("jifu87ujasef").
        Chacha20().
        Decrypt()
    cyptdeStr := cyptde.ToString()

    assertError(cyptde.Error(), "Test_Chacha20-Decode")

    assert(data, cyptdeStr, "Test_Chacha20")
}

func Test_Chacha20poly1305(t *testing.T) {
    assert := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    data := "test-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-pass"
    cypt := FromString(data).
        SetKey("dfertf12dfdfertf12dfdfertf12df12").
        SetIv("jifu87ujasef").
        Chacha20poly1305([]byte("test123")).
        Encrypt()
    cyptStr := cypt.ToBase64String()

    assertError(cypt.Error(), "Test_Chacha20poly1305-Encode")

    cyptde := FromBase64String(cyptStr).
        SetKey("dfertf12dfdfertf12dfdfertf12df12").
        SetIv("jifu87ujasef").
        Chacha20poly1305([]byte("test123")).
        Decrypt()
    cyptdeStr := cyptde.ToString()

    assertError(cyptde.Error(), "Test_Chacha20poly1305-Decode")

    assert(data, cyptdeStr, "Test_Chacha20poly1305")
}
