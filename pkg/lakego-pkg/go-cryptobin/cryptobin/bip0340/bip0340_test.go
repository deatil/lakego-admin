package bip0340

import (
    "testing"
    "crypto/rand"

    cryptobin_test "github.com/deatil/go-cryptobin/tool/test"
)

func Test_PublickeyXY(t *testing.T) {
    assertNoError := cryptobin_test.AssertNoErrorT(t)
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    obj := GenerateKey("S256")

    assertNoError(obj.Error(), "PublickeyXY")

    x := obj.GetPublicKeyUncompressString()
    xx := obj.GetPublicKeyCompressString()

    assertNotEmpty(x, "PublickeyXY-x")
    assertNotEmpty(xx, "PublickeyXY-xx")

    xk := New().SetCurve("S256").FromPublicKeyUncompressString(x)
    xxk := New().SetCurve("S256").FromPublicKeyCompressString(xx)

    assertNoError(xk.Error(), "PublickeyXY-xk")
    assertNoError(xxk.Error(), "PublickeyXY-xxk")

    assertEqual(xk.GetPublicKey(), obj.GetPublicKey(), "PublickeyXY-xk")
    assertEqual(xxk.GetPublicKey(), obj.GetPublicKey(), "PublickeyXY-xxk")

}

func Test_PublickeyXY_2(t *testing.T) {
    assertNoError := cryptobin_test.AssertNoErrorT(t)
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    obj := GenerateKey("S256")

    assertNoError(obj.Error(), "PublickeyXY")

    x := obj.GetPublicKeyUncompressString()
    xx := obj.GetPublicKeyCompressString()

    assertNotEmpty(x, "PublickeyXY-x")
    assertNotEmpty(xx, "PublickeyXY-xx")

    xk := New().SetCurve("S256").FromPublicKeyString(x)
    xxk := New().SetCurve("S256").FromPublicKeyString(xx)

    assertNoError(xk.Error(), "PublickeyXY-xk")
    assertNoError(xxk.Error(), "PublickeyXY-xxk")

    assertEqual(xk.GetPublicKey(), obj.GetPublicKey(), "PublickeyXY-xk")
    assertEqual(xxk.GetPublicKey(), obj.GetPublicKey(), "PublickeyXY-xxk")

}

func Test_PublickeyXY_String(t *testing.T) {
    assertNoError := cryptobin_test.AssertNoErrorT(t)
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    obj := GenerateKey("S256")

    assertNoError(obj.Error(), "PublickeyXY_3")

    x := obj.GetPublicKeyXString()
    y := obj.GetPublicKeyYString()

    assertNotEmpty(x, "PublickeyXY_3-x")
    assertNotEmpty(y, "PublickeyXY_3-y")

    xk := New().SetCurve("S256").FromPublicKeyXYString(x, y)

    assertNoError(xk.Error(), "PublickeyXY_3-xk")
    assertEqual(xk.GetPublicKey(), obj.GetPublicKey(), "PublickeyXY_3-xk")
}

func Test_PublickeyXY_Bytes(t *testing.T) {
    assertNoError := cryptobin_test.AssertNoErrorT(t)
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    obj := GenerateKey("S256")

    assertNoError(obj.Error(), "PublickeyXY_Bytes")

    pub := obj.GetPublicKey()

    x := pub.X.Bytes()
    y := pub.Y.Bytes()

    assertNotEmpty(x, "PublickeyXY_Bytes-x")
    assertNotEmpty(y, "PublickeyXY_Bytes-y")

    xk := New().SetCurve("S256").FromPublicKeyXYBytes(x, y)

    assertNoError(xk.Error(), "PublickeyXY_Bytes-xk")
    assertEqual(xk.GetPublicKey(), obj.GetPublicKey(), "PublickeyXY_Bytes-xk")
}

func Test_PrivateKeyD(t *testing.T) {
    assertNoError := cryptobin_test.AssertNoErrorT(t)
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    obj := GenerateKey("S256")

    assertNoError(obj.Error(), "PrivateKeyD")

    d := obj.GetPrivateKeyString()

    assertNotEmpty(d, "PrivateKeyD")

    xk := New().SetCurve("S256").FromPrivateKeyString(d)

    assertNoError(xk.Error(), "PrivateKeyD-xk")

    assertEqual(xk.GetPrivateKey(), obj.GetPrivateKey(), "PrivateKeyD-xk")
}

func Test_PrivateKey_Bytes(t *testing.T) {
    assertNoError := cryptobin_test.AssertNoErrorT(t)
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    obj := GenerateKey("S256")

    assertNoError(obj.Error(), "PrivateKeyD")

    priv := obj.GetPrivateKey()

    d := priv.D.Bytes()

    assertNotEmpty(d, "PrivateKey_Bytes")

    xk := New().SetCurve("S256").FromPrivateKeyBytes(d)

    assertNoError(xk.Error(), "PrivateKey_Bytes-xk")

    assertEqual(xk.GetPrivateKey(), obj.GetPrivateKey(), "PrivateKey_Bytes-xk")
}

func Test_GetPrivateKeyString(t *testing.T) {
    assertNoError := cryptobin_test.AssertNoErrorT(t)
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    obj := GenerateKey("S256")
    assertNoError(obj.Error(), "GetPrivateKeyString")

    priv := obj.GetPrivateKeyString()
    assertNotEmpty(priv, "GetPrivateKeyString")

    xk := New().SetCurve("S256").FromPrivateKeyString(priv)

    assertNoError(xk.Error(), "GetPrivateKeyString-xk")
    assertEqual(xk.GetPrivateKey(), obj.GetPrivateKey(), "GetPrivateKeyString-xk")
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
    for _, cipher := range testPEMCiphers{
        test_CreatePKCS1PrivateKeyWithPassword(t, cipher)
    }
}

func test_CreatePKCS1PrivateKeyWithPassword(t *testing.T, cipher string) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertNoError := cryptobin_test.AssertNoErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    t.Run(cipher, func(t *testing.T) {
        pass := make([]byte, 12)
        _, err := rand.Read(pass)
        if err != nil {
            t.Fatal(err)
        }

        gen := New().GenerateKey()

        prikey := gen.GetPrivateKey()

        pri := gen.
            CreatePKCS1PrivateKeyWithPassword(string(pass), cipher).
            ToKeyString()

        assertNoError(gen.Error(), "Test_CreatePKCS1PrivateKeyWithPassword")
        assertNotEmpty(pri, "Test_CreatePKCS1PrivateKeyWithPassword-pri")

        newPrikey := New().
            FromPKCS1PrivateKeyWithPassword([]byte(pri), string(pass)).
            GetPrivateKey()

        assertNotEmpty(newPrikey, "Test_CreatePKCS1PrivateKeyWithPassword-newPrikey")

        assertEqual(newPrikey, prikey, "Test_CreatePKCS1PrivateKeyWithPassword")
    })
}

func Test_PKCS8PrivateKey_Der(t *testing.T) {
    assertNoError := cryptobin_test.AssertNoErrorT(t)
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    obj := GenerateKey("S256")
    assertNoError(obj.Error(), "PKCS8PrivateKey_Der")

    privDer := obj.
        CreatePKCS8PrivateKey().
        MakeKeyDer().
        ToKeyBytes()
    assertNotEmpty(privDer, "PKCS8PrivateKey_Der-der")

    res := New().
        SetCurve("S256").
        FromPKCS8PrivateKeyDer(privDer)
    assertNoError(res.Error(), "PKCS8PrivateKey_Der-res")

    assertEqual(res.GetPrivateKey(), obj.GetPrivateKey(), "PKCS8PrivateKey_Der-res")
}

func Test_PKCS1PrivateKey_Der(t *testing.T) {
    assertNoError := cryptobin_test.AssertNoErrorT(t)
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    obj := GenerateKey("S256")
    assertNoError(obj.Error(), "PKCS1PrivateKey_Der")

    privDer := obj.
        CreatePKCS1PrivateKey().
        MakeKeyDer().
        ToKeyBytes()
    assertNotEmpty(privDer, "PKCS1PrivateKey_Der-der")

    res := New().
        SetCurve("S256").
        FromPKCS1PrivateKeyDer(privDer)
    assertNoError(res.Error(), "PKCS1PrivateKey_Der-res")

    assertEqual(res.GetPrivateKey(), obj.GetPrivateKey(), "PKCS1PrivateKey_Der-res")
}

func Test_PublicKey_Der(t *testing.T) {
    assertNoError := cryptobin_test.AssertNoErrorT(t)
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    obj := GenerateKey("S256")
    assertNoError(obj.Error(), "PublicKey_Der")

    privDer := obj.
        CreatePublicKey().
        MakeKeyDer().
        ToKeyBytes()
    assertNotEmpty(privDer, "PublicKey_Der-der")

    res := New().
        SetCurve("S256").
        FromPublicKeyDer(privDer)
    assertNoError(res.Error(), "PublicKey_Der-res")

    assertEqual(res.GetPublicKey(), obj.GetPublicKey(), "PublicKey_Der-res")
}

func Test_EncodingType(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)

    var ecdsa BIP0340

    ecdsa = NewBIP0340().WithEncoding(EncodingASN1)
    assertEqual(ecdsa.encoding, EncodingASN1, "EncodingASN1 1")

    ecdsa = NewBIP0340().WithEncodingASN1()
    assertEqual(ecdsa.encoding, EncodingASN1, "EncodingASN1")

    ecdsa = NewBIP0340().WithEncodingBytes()
    assertEqual(ecdsa.encoding, EncodingBytes, "EncodingBytes")

    ecdsa = BIP0340{
        encoding: EncodingASN1,
    }
    assertEqual(ecdsa.GetEncoding(), EncodingASN1, "new EncodingASN1")

    ecdsa = BIP0340{
        encoding: EncodingBytes,
    }
    assertEqual(ecdsa.GetEncoding(), EncodingBytes, "new EncodingBytes")
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
    assertTrue := cryptobin_test.AssertTrueT(t)
    assertNoError := cryptobin_test.AssertNoErrorT(t)

    gen := GenerateKey("S256")

    data := "test-pass"

    // 签名
    objSign := gen.
        FromString(data).
        WithEncoding(encoding).
        Sign()
    signed := objSign.ToBase64String()

    assertNoError(objSign.Error(), "test_SignWithEncoding-Sign")
    assertNotEmpty(signed, "test_SignWithEncoding-Sign")

    // 验证
    objVerify := gen.
        FromBase64String(signed).
        WithEncoding(encoding).
        Verify([]byte(data))

    assertNoError(objVerify.Error(), "test_SignWithEncoding-Verify")
    assertTrue(objVerify.ToVerify(), "test_SignWithEncoding-Verify")
}

func Test_SignWithEncoding_Two_Check(t *testing.T) {
    assertNoError := cryptobin_test.AssertNoErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)
    assertNotEqual := cryptobin_test.AssertNotEqualT(t)

    data := "test-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-passtest-pass"

    gen := GenerateKey("S256")

    // 签名
    objSign := gen.
        FromString(data).
        WithEncoding(EncodingASN1).
        Sign()
    signed := objSign.ToBase64String()

    assertNoError(objSign.Error(), "Test_SignWithEncoding_Two_Check-Sign")
    assertNotEmpty(signed, "Test_SignWithEncoding_Two_Check-Sign")

    // 签名
    objSign2 := gen.
        FromString(data).
        WithEncoding(EncodingBytes).
        Sign()
    signed2 := objSign2.ToBase64String()

    assertNoError(objSign2.Error(), "Test_SignWithEncoding_Two_Check-Sign")
    assertNotEmpty(signed2, "Test_SignWithEncoding_Two_Check-Sign")

    assertNotEqual(signed2, signed, "Test_SignWithEncoding_Two_Check")
}

func Test_GenKey(t *testing.T) {
    cases := []string{
        "P521",
        "P384",
        "P256",
        "P224",
        "S256",
    }

    for _, c := range cases {
        t.Run(c, func(t *testing.T) {
            test_GenKey(t, c)
        })
    }
}

func test_GenKey(t *testing.T, curve string) {
    assertNoError := cryptobin_test.AssertNoErrorT(t)
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    obj := GenerateKey(curve)

    assertNoError(obj.Error(), "PrivateKeyD")

    d := obj.GetPrivateKeyString()

    assertNotEmpty(d, "PrivateKeyD")

    xk := New().SetCurve(curve).FromPrivateKeyString(d)

    assertNoError(xk.Error(), "PrivateKeyD-xk")

    assertEqual(xk.GetPrivateKey(), obj.GetPrivateKey(), "Test_GenKey-xk")
}
