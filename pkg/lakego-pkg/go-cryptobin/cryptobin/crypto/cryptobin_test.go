package crypto

import (
    "testing"

    cryptobin_test "github.com/deatil/go-cryptobin/tool/test"
)

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
        Salsa20("1234567890abcdef").
        Encrypt()
    cyptStr := cypt.ToBase64String()

    assertError(cypt.Error(), "Salsa20-Encode")

    cyptde := FromBase64String(cyptStr).
        SetKey("1234567890abcdef1234567890abcdef").
        Salsa20("1234567890abcdef").
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
        "DESDerivedSbox",
        "TestSbox",
        "CryptoProSbox",
        "SboxIdtc26gost28147paramZ",
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
    cypt := FromString(data).
        SetKey("dfertf12dfertf12").
        SetIv("dfertf12dfertf12").
        Aes().
        OCB("dfertf12dfertf").
        PKCS7Padding().
        Encrypt()
    cyptStr := cypt.ToBase64String()

    assertError(cypt.Error(), "AesOCBPKCS7Padding-Encode")

    cyptde := FromBase64String(cyptStr).
        SetKey("dfertf12dfertf12").
        SetIv("dfertf12dfertf12").
        Aes().
        OCB("dfertf12dfertf").
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
        SetIv("dfertf12dfertf12").
        Aes().
        EAX("dfertf12dfertf").
        PKCS7Padding().
        Encrypt()
    cyptStr := cypt.ToBase64String()

    assertError(cypt.Error(), "AesOCBPKCS7Padding-Encode")

    cyptde := FromBase64String(cyptStr).
        SetKey("dfertf12dfertf12").
        SetIv("dfertf12dfertf12").
        Aes().
        EAX("dfertf12dfertf").
        PKCS7Padding().
        Decrypt()
    cyptdeStr := cyptde.ToString()

    assertError(cyptde.Error(), "AesOCBPKCS7Padding-Decode")

    assert(data, cyptdeStr, "AesOCBPKCS7Padding")
}

func Test_AesCCMPKCS7Padding(t *testing.T) {
    assert := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    data := "test-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-pass"
    cypt := FromString(data).
        SetKey("dfertf12dfertf12").
        SetIv("dfertf12dfertf12").
        Aes().
        CCM("dfertf12dfe").
        PKCS7Padding().
        Encrypt()
    cyptStr := cypt.ToBase64String()

    assertError(cypt.Error(), "AesCCMPKCS7Padding-Encode")

    cyptde := FromBase64String(cyptStr).
        SetKey("dfertf12dfertf12").
        SetIv("dfertf12dfertf12").
        Aes().
        CCM("dfertf12dfe").
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
