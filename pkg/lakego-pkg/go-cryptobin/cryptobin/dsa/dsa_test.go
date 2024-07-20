package dsa

import (
    "testing"
    "crypto/rand"

    cryptobin_test "github.com/deatil/go-cryptobin/tool/test"
)

var (
    prikeyXML = `
<DSAKeyValue>
    <P>81XZh1ZNtyTnT9lkaZnM1jZeR1yTQksP2wxQCzNSvJf0r2men7z+lYy6SccAHd8X8JRxm7PlkN2vMqGggE+Abw7ftMgfopwcSPd2CuC825K2RzB8Jfa0hEb9qwAkTkQ/SI/xwXgMGhkIiK2wF4IiMyKoxFP8/dUgzUHNjzm46DsPVmHvwB9rF0DIp5+NnTKo5qA64tP3ULgGy+FQ8E0gc4nVjsRBJwnzJF3vPWZjZwufQHE3axoGgUbMVk6X+ZnHDP+sMoNXGo4VypPJgWX7GFGRw1P3XJ2/Vaj3OI17PZgalzN+rhu8BAQ6oikwvt8CJ6nGMCd9f3ammDTzfqJzxQ==</P>
    <Q>qiNxZYHeUeDOuDKJTmpkEpyTEPguq5DPyEntEQ==</Q>
    <G>qnmTL0JxOxUcwmrZPsqV5wKgg3BhBqXzP40O8BBYGG8deNWFWB6BkgOSIybssGZdm/NDfIHgyDvtmau7gkI3QujOeyWs76o7F7PRI5GgOPlurpvktTLT9lLdRvd+lK0wKZJuWzOhnR2LpTVCV8oJGIIRlqYVmrEMcxoQtWkBBJx9IYFi8Rnrpo/BdxsbkxF+GPh7t0zNZxF7BraIY7MaNprvHLFCOVQ9A7kityJHylElCmZ665ZP5nDdsVGyvF9pc7rj1tRk1M5Q4gF3exlbQFB+nfLw6OGICxAYCoQ60Anw/oa4j/8l0vQMcfmpJMm5GFZyqh+ps/LC1MiQEORlmQ==</G>
    <Y>yvFanSGUiiyzuq8lYeXFFbB4TLHIcNcdrj0ulUujLp+7SbjLTzkdzaSzV3TGrwfzOQqOfbBdruZzK3sSZ8y1/d8ytyU0nRtl19xBbqh/BQ8SEw+vDh2e5tErMJcT5vp6Av4L8krbChzavCoksXf3nBkTRJPFoMuvWU3k7FLSu8UEdhwEug2xtQznqRk8qqDZy4U8eP1nLjpsDF8dXtaCYywV+0KNk8YInqaj99/fhDk56HWiazSa+5uv+fviTsYBqKHMDDrs59GfTHQI0xnAG6XXNHCMocfKXnPUWw0WtN4r19JIHnoIPUmdUX98ujXiZ0QqYeiLDrFqTqdEATLNoA==</Y>
    <X>a+fL1Qm1mxUEaGJ6DNfWla5v4Su3XxABKNAjqg==</X>
</DSAKeyValue>
    `

    pubkeyXML = `
<DSAKeyValue>
    <P>81XZh1ZNtyTnT9lkaZnM1jZeR1yTQksP2wxQCzNSvJf0r2men7z+lYy6SccAHd8X8JRxm7PlkN2vMqGggE+Abw7ftMgfopwcSPd2CuC825K2RzB8Jfa0hEb9qwAkTkQ/SI/xwXgMGhkIiK2wF4IiMyKoxFP8/dUgzUHNjzm46DsPVmHvwB9rF0DIp5+NnTKo5qA64tP3ULgGy+FQ8E0gc4nVjsRBJwnzJF3vPWZjZwufQHE3axoGgUbMVk6X+ZnHDP+sMoNXGo4VypPJgWX7GFGRw1P3XJ2/Vaj3OI17PZgalzN+rhu8BAQ6oikwvt8CJ6nGMCd9f3ammDTzfqJzxQ==</P>
    <Q>qiNxZYHeUeDOuDKJTmpkEpyTEPguq5DPyEntEQ==</Q>
    <G>qnmTL0JxOxUcwmrZPsqV5wKgg3BhBqXzP40O8BBYGG8deNWFWB6BkgOSIybssGZdm/NDfIHgyDvtmau7gkI3QujOeyWs76o7F7PRI5GgOPlurpvktTLT9lLdRvd+lK0wKZJuWzOhnR2LpTVCV8oJGIIRlqYVmrEMcxoQtWkBBJx9IYFi8Rnrpo/BdxsbkxF+GPh7t0zNZxF7BraIY7MaNprvHLFCOVQ9A7kityJHylElCmZ665ZP5nDdsVGyvF9pc7rj1tRk1M5Q4gF3exlbQFB+nfLw6OGICxAYCoQ60Anw/oa4j/8l0vQMcfmpJMm5GFZyqh+ps/LC1MiQEORlmQ==</G>
    <Y>yvFanSGUiiyzuq8lYeXFFbB4TLHIcNcdrj0ulUujLp+7SbjLTzkdzaSzV3TGrwfzOQqOfbBdruZzK3sSZ8y1/d8ytyU0nRtl19xBbqh/BQ8SEw+vDh2e5tErMJcT5vp6Av4L8krbChzavCoksXf3nBkTRJPFoMuvWU3k7FLSu8UEdhwEug2xtQznqRk8qqDZy4U8eP1nLjpsDF8dXtaCYywV+0KNk8YInqaj99/fhDk56HWiazSa+5uv+fviTsYBqKHMDDrs59GfTHQI0xnAG6XXNHCMocfKXnPUWw0WtN4r19JIHnoIPUmdUX98ujXiZ0QqYeiLDrFqTqdEATLNoA==</Y>
</DSAKeyValue>
    `
)

func Test_XMLSign(t *testing.T) {
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)
    assertBool := cryptobin_test.AssertBoolT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    data := "test-pass"

    // 签名
    objSign := NewDSA().
        FromString(data).
        FromXMLPrivateKey([]byte(prikeyXML)).
        Sign()
    signed := objSign.ToBase64String()

    assertError(objSign.Error(), "XMLSign-Sign")
    assertNotEmpty(signed, "XMLSign-Sign")

    // 验证
    objVerify := NewDSA().
        FromBase64String(signed).
        FromXMLPublicKey([]byte(pubkeyXML)).
        Verify([]byte(data))

    assertError(objVerify.Error(), "XMLSign-Verify")
    assertBool(objVerify.ToVerify(), "XMLSign-Verify")
}

func Test_XMLSignASN1(t *testing.T) {
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)
    assertBool := cryptobin_test.AssertBoolT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    data := "test-pass"

    // 签名
    objSign := NewDSA().
        FromString(data).
        FromXMLPrivateKey([]byte(prikeyXML)).
        SignASN1()
    signed := objSign.ToBase64String()

    assertError(objSign.Error(), "XMLSignASN1-Sign")
    assertNotEmpty(signed, "XMLSignASN1-Sign")

    // 验证
    objVerify := NewDSA().
        FromBase64String(signed).
        FromXMLPublicKey([]byte(pubkeyXML)).
        VerifyASN1([]byte(data))

    assertError(objVerify.Error(), "XMLSignASN1-Verify")
    assertBool(objVerify.ToVerify(), "XMLSignASN1-Verify")
}

func Test_XMLSignBytes(t *testing.T) {
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)
    assertBool := cryptobin_test.AssertBoolT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    data := "test-pass"

    // 签名
    objSign := NewDSA().
        FromString(data).
        FromXMLPrivateKey([]byte(prikeyXML)).
        SignBytes()
    signed := objSign.ToBase64String()

    assertError(objSign.Error(), "XMLSignBytes-Sign")
    assertNotEmpty(signed, "XMLSignBytes-Sign")

    // 验证
    objVerify := NewDSA().
        FromBase64String(signed).
        FromXMLPublicKey([]byte(pubkeyXML)).
        VerifyBytes([]byte(data))

    assertError(objVerify.Error(), "XMLSignBytes-Verify")
    assertBool(objVerify.ToVerify(), "XMLSignBytes-Verify")
}

func Test_XMLSignWithSeparator(t *testing.T) {
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)
    assertBool := cryptobin_test.AssertBoolT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    data := "test-pass"

    // 签名
    objSign := NewDSA().
        FromString(data).
        FromXMLPrivateKey([]byte(prikeyXML)).
        SignWithSeparator()
    signed := objSign.ToBase64String()

    assertError(objSign.Error(), "SignWithSeparator-Sign")
    assertNotEmpty(signed, "SignWithSeparator-Sign")

    // 验证
    objVerify := NewDSA().
        FromBase64String(signed).
        FromXMLPublicKey([]byte(pubkeyXML)).
        VerifyWithSeparator([]byte(data))

    assertError(objVerify.Error(), "SignWithSeparator-Verify")
    assertBool(objVerify.ToVerify(), "SignWithSeparator-Verify")
}

var testPEMCiphers = []string{
    "DESCBC",
    "DESEDE3CBC",
    "AES128CBC",
    "AES192CBC",
    "AES256CBC",

    "DESCFB",
    "DESEDE3CFB",
    "AES128CFB",
    "AES192CFB",
    "AES256CFB",

    "DESOFB",
    "DESEDE3OFB",
    "AES128OFB",
    "AES192OFB",
    "AES256OFB",

    "DESCTR",
    "DESEDE3CTR",
    "AES128CTR",
    "AES192CTR",
    "AES256CTR",
}

func Test_CreatePKCS1PrivateKeyWithPassword(t *testing.T) {
    gen := New().GenerateKey("L2048N224")

    for _, cipher := range testPEMCiphers{
        test_CreatePKCS1PrivateKeyWithPassword(t, gen, cipher)
    }
}

func test_CreatePKCS1PrivateKeyWithPassword(t *testing.T, gen DSA, cipher string) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    t.Run(cipher, func(t *testing.T) {
        pass := make([]byte, 12)
        _, err := rand.Read(pass)
        if err != nil {
            t.Fatal(err)
        }

        prikey := gen.GetPrivateKey()

        pri := gen.
            CreatePKCS1PrivateKeyWithPassword(string(pass), cipher).
            ToKeyString()

        assertError(gen.Error(), "Test_CreatePKCS1PrivateKeyWithPassword")
        assertNotEmpty(pri, "Test_CreatePKCS1PrivateKeyWithPassword-pri")

        newPrikey := New().
            FromPKCS1PrivateKeyWithPassword([]byte(pri), string(pass)).
            GetPrivateKey()

        assertNotEmpty(newPrikey, "Test_CreatePKCS1PrivateKeyWithPassword-newPrikey")

        assertEqual(newPrikey, prikey, "Test_CreatePKCS1PrivateKeyWithPassword")
    })
}

func Test_SignBytes(t *testing.T) {
    types := []string{
        "L1024N160",
        "L2048N224",
        "L2048N256",
        "L3072N256",
    }

    for _, name := range types {
        t.Run(name, func(t *testing.T) {
            gen := New().GenerateKey(name)
            test_SignBytes(t, gen)
        })
    }
}

func test_SignBytes(t *testing.T, gen DSA) {
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)
    assertBool := cryptobin_test.AssertBoolT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    data := "test-pass"

    // 签名
    objSign := gen.
        FromString(data).
        SignBytes()
    signed := objSign.ToBase64String()

    assertError(objSign.Error(), "SignBytes-Sign")
    assertNotEmpty(signed, "SignBytes-Sign")

    // 验证
    objVerify := gen.
        FromBase64String(signed).
        VerifyBytes([]byte(data))

    assertError(objVerify.Error(), "SignBytes-Verify")
    assertBool(objVerify.ToVerify(), "SignBytes-Verify")
}

func Test_EncodingType(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)

    var dsa DSA

    dsa = NewDSA().WithEncoding(EncodingASN1)
    assertEqual(dsa.encoding, EncodingASN1, "EncodingASN1 1")

    dsa = NewDSA().WithEncodingASN1()
    assertEqual(dsa.encoding, EncodingASN1, "EncodingASN1")

    dsa = NewDSA().WithEncodingBytes()
    assertEqual(dsa.encoding, EncodingBytes, "EncodingBytes")

    dsa = DSA{
        encoding: EncodingASN1,
    }
    assertEqual(dsa.GetEncoding(), EncodingASN1, "new EncodingASN1")

    dsa = DSA{
        encoding: EncodingBytes,
    }
    assertEqual(dsa.GetEncoding(), EncodingBytes, "new EncodingBytes")
}

func Test_SignWithEncoding(t *testing.T) {
    t.Run("EncodingASN1", func(t *testing.T) {
        test_SignWithEncoding(t, EncodingASN1)
    })
    t.Run("EncodingBytes", func(t *testing.T) {
        test_SignWithEncoding(t, EncodingBytes)
    })
}

func test_SignWithEncoding(t *testing.T, encoding EncodingType) {
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)
    assertBool := cryptobin_test.AssertBoolT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    gen := GenerateKey("L1024N160")

    data := "test-pass"

    // 签名
    objSign := gen.
        FromString(data).
        WithEncoding(encoding).
        Sign()
    signed := objSign.ToBase64String()

    assertError(objSign.Error(), "test_SignWithEncoding-Sign")
    assertNotEmpty(signed, "test_SignWithEncoding-Sign")

    // 验证
    objVerify := gen.
        FromBase64String(signed).
        WithEncoding(encoding).
        Verify([]byte(data))

    assertError(objVerify.Error(), "test_SignWithEncoding-Verify")
    assertBool(objVerify.ToVerify(), "test_SignWithEncoding-Verify")
}

func Test_SignWithEncoding_Two_Check(t *testing.T) {
    assertError := cryptobin_test.AssertErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)
    assertNotEqual := cryptobin_test.AssertNotEqualT(t)

    data := "test-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-pass"

    gen := GenerateKey("L1024N160")

    // 签名
    objSign := gen.
        FromString(data).
        WithEncoding(EncodingASN1).
        Sign()
    signed := objSign.ToBase64String()

    assertError(objSign.Error(), "Test_SignWithEncoding_Two_Check-Sign")
    assertNotEmpty(signed, "Test_SignWithEncoding_Two_Check-Sign")

    // 签名
    objSign2 := gen.
        FromString(data).
        WithEncoding(EncodingBytes).
        Sign()
    signed2 := objSign2.ToBase64String()

    assertError(objSign2.Error(), "Test_SignWithEncoding_Two_Check-Sign")
    assertNotEmpty(signed2, "Test_SignWithEncoding_Two_Check-Sign")

    assertNotEqual(signed2, signed, "Test_SignWithEncoding_Two_Check")
}
