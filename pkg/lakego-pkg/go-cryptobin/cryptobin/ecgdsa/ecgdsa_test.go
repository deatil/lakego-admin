package ecgdsa

import (
    "testing"
    "crypto/rand"

    cryptobin_test "github.com/deatil/go-cryptobin/tool/test"
)

func Test_PublickeyXY(t *testing.T) {
    assertError := cryptobin_test.AssertErrorT(t)
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    obj := GenerateKey("P256")

    assertError(obj.Error(), "PublickeyXY")

    x := obj.GetPublicKeyUncompressString()
    xx := obj.GetPublicKeyCompressString()

    assertNotEmpty(x, "PublickeyXY-x")
    assertNotEmpty(xx, "PublickeyXY-xx")

    xk := New().SetCurve("P256").FromPublicKeyUncompressString(x)
    xxk := New().SetCurve("P256").FromPublicKeyCompressString(xx)

    assertError(xk.Error(), "PublickeyXY-xk")
    assertError(xxk.Error(), "PublickeyXY-xxk")

    assertEqual(xk.GetPublicKey(), obj.GetPublicKey(), "PublickeyXY-xk")
    assertEqual(xxk.GetPublicKey(), obj.GetPublicKey(), "PublickeyXY-xxk")

}

func Test_PublickeyXY_2(t *testing.T) {
    assertError := cryptobin_test.AssertErrorT(t)
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    obj := GenerateKey("P256")

    assertError(obj.Error(), "PublickeyXY")

    x := obj.GetPublicKeyUncompressString()
    xx := obj.GetPublicKeyCompressString()

    assertNotEmpty(x, "PublickeyXY-x")
    assertNotEmpty(xx, "PublickeyXY-xx")

    xk := New().SetCurve("P256").FromPublicKeyString(x)
    xxk := New().SetCurve("P256").FromPublicKeyString(xx)

    assertError(xk.Error(), "PublickeyXY-xk")
    assertError(xxk.Error(), "PublickeyXY-xxk")

    assertEqual(xk.GetPublicKey(), obj.GetPublicKey(), "PublickeyXY-xk")
    assertEqual(xxk.GetPublicKey(), obj.GetPublicKey(), "PublickeyXY-xxk")

}

func Test_PublickeyXY_String(t *testing.T) {
    assertError := cryptobin_test.AssertErrorT(t)
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    obj := GenerateKey("P256")

    assertError(obj.Error(), "PublickeyXY_3")

    x := obj.GetPublicKeyXString()
    y := obj.GetPublicKeyYString()

    assertNotEmpty(x, "PublickeyXY_3-x")
    assertNotEmpty(y, "PublickeyXY_3-y")

    xk := New().SetCurve("P256").FromPublicKeyXYString(x, y)

    assertError(xk.Error(), "PublickeyXY_3-xk")
    assertEqual(xk.GetPublicKey(), obj.GetPublicKey(), "PublickeyXY_3-xk")
}

func Test_PublickeyXY_Bytes(t *testing.T) {
    assertError := cryptobin_test.AssertErrorT(t)
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    obj := GenerateKey("P256")

    assertError(obj.Error(), "PublickeyXY_Bytes")

    pub := obj.GetPublicKey()

    x := pub.X.Bytes()
    y := pub.Y.Bytes()

    assertNotEmpty(x, "PublickeyXY_Bytes-x")
    assertNotEmpty(y, "PublickeyXY_Bytes-y")

    xk := New().SetCurve("P256").FromPublicKeyXYBytes(x, y)

    assertError(xk.Error(), "PublickeyXY_Bytes-xk")
    assertEqual(xk.GetPublicKey(), obj.GetPublicKey(), "PublickeyXY_Bytes-xk")
}

func Test_PrivateKeyD(t *testing.T) {
    assertError := cryptobin_test.AssertErrorT(t)
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    obj := GenerateKey("P256")

    assertError(obj.Error(), "PrivateKeyD")

    d := obj.GetPrivateKeyString()

    assertNotEmpty(d, "PrivateKeyD")

    xk := New().SetCurve("P256").FromPrivateKeyString(d)

    assertError(xk.Error(), "PrivateKeyD-xk")

    assertEqual(xk.GetPrivateKey(), obj.GetPrivateKey(), "PrivateKeyD-xk")
}

func Test_PrivateKey_Bytes(t *testing.T) {
    assertError := cryptobin_test.AssertErrorT(t)
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    obj := GenerateKey("P256")

    assertError(obj.Error(), "PrivateKeyD")

    priv := obj.GetPrivateKey()

    d := priv.D.Bytes()

    assertNotEmpty(d, "PrivateKey_Bytes")

    xk := New().SetCurve("P256").FromPrivateKeyBytes(d)

    assertError(xk.Error(), "PrivateKey_Bytes-xk")

    assertEqual(xk.GetPrivateKey(), obj.GetPrivateKey(), "PrivateKey_Bytes-xk")
}

func Test_GetPrivateKeyString(t *testing.T) {
    assertError := cryptobin_test.AssertErrorT(t)
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    obj := GenerateKey("P256")
    assertError(obj.Error(), "GetPrivateKeyString")

    priv := obj.GetPrivateKeyString()
    assertNotEmpty(priv, "GetPrivateKeyString")

    xk := New().SetCurve("P256").FromPrivateKeyString(priv)

    assertError(xk.Error(), "GetPrivateKeyString-xk")
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
    assertError := cryptobin_test.AssertErrorT(t)
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

        assertError(gen.Error(), "Test_CreatePKCS1PrivateKeyWithPassword")
        assertNotEmpty(pri, "Test_CreatePKCS1PrivateKeyWithPassword-pri")

        newPrikey := New().
            FromPKCS1PrivateKeyWithPassword([]byte(pri), string(pass)).
            GetPrivateKey()

        assertNotEmpty(newPrikey, "Test_CreatePKCS1PrivateKeyWithPassword-newPrikey")

        assertEqual(newPrikey, prikey, "Test_CreatePKCS1PrivateKeyWithPassword")
    })
}

func Test_PKCS8PrivateKey_Der(t *testing.T) {
    assertError := cryptobin_test.AssertErrorT(t)
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    obj := GenerateKey("P256")
    assertError(obj.Error(), "PKCS8PrivateKey_Der")

    privDer := obj.
        CreatePKCS8PrivateKey().
        MakeKeyDer().
        ToKeyBytes()
    assertNotEmpty(privDer, "PKCS8PrivateKey_Der-der")

    res := New().
        SetCurve("P256").
        FromPKCS8PrivateKeyDer(privDer)
    assertError(res.Error(), "PKCS8PrivateKey_Der-res")

    assertEqual(res.GetPrivateKey(), obj.GetPrivateKey(), "PKCS8PrivateKey_Der-res")
}

func Test_PKCS1PrivateKey_Der(t *testing.T) {
    assertError := cryptobin_test.AssertErrorT(t)
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    obj := GenerateKey("P256")
    assertError(obj.Error(), "PKCS1PrivateKey_Der")

    privDer := obj.
        CreatePKCS1PrivateKey().
        MakeKeyDer().
        ToKeyBytes()
    assertNotEmpty(privDer, "PKCS1PrivateKey_Der-der")

    res := New().
        SetCurve("P256").
        FromPKCS1PrivateKeyDer(privDer)
    assertError(res.Error(), "PKCS1PrivateKey_Der-res")

    assertEqual(res.GetPrivateKey(), obj.GetPrivateKey(), "PKCS1PrivateKey_Der-res")
}

func Test_PublicKey_Der(t *testing.T) {
    assertError := cryptobin_test.AssertErrorT(t)
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    obj := GenerateKey("P256")
    assertError(obj.Error(), "PublicKey_Der")

    privDer := obj.
        CreatePublicKey().
        MakeKeyDer().
        ToKeyBytes()
    assertNotEmpty(privDer, "PublicKey_Der-der")

    res := New().
        SetCurve("P256").
        FromPublicKeyDer(privDer)
    assertError(res.Error(), "PublicKey_Der-res")

    assertEqual(res.GetPublicKey(), obj.GetPublicKey(), "PublicKey_Der-res")
}

func Test_EncodingType(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)

    var ecdsa ECGDSA

    ecdsa = NewECGDSA().WithEncoding(EncodingASN1)
    assertEqual(ecdsa.encoding, EncodingASN1, "EncodingASN1 1")

    ecdsa = NewECGDSA().WithEncodingASN1()
    assertEqual(ecdsa.encoding, EncodingASN1, "EncodingASN1")

    ecdsa = NewECGDSA().WithEncodingBytes()
    assertEqual(ecdsa.encoding, EncodingBytes, "EncodingBytes")

    ecdsa = ECGDSA{
        encoding: EncodingASN1,
    }
    assertEqual(ecdsa.GetEncoding(), EncodingASN1, "new EncodingASN1")

    ecdsa = ECGDSA{
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
    assertBool := cryptobin_test.AssertBoolT(t)
    assertError := cryptobin_test.AssertErrorT(t)

    gen := GenerateKey("P256")

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

    gen := GenerateKey("P256")

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

func Test_GenKey(t *testing.T) {
    cases := []string{
        "P521",
        "P384",
        "P256",
        "P224",

        "BrainpoolP256r1",
        "BrainpoolP256t1",
        "BrainpoolP320r1",
        "BrainpoolP320t1",
        "BrainpoolP384r1",
        "BrainpoolP384t1",
        "BrainpoolP512r1",
        "BrainpoolP512t1",
    }

    for _, c := range cases {
        t.Run(c, func(t *testing.T) {
            test_GenKey(t, c)
        })
    }
}

func test_GenKey(t *testing.T, curve string) {
    assertError := cryptobin_test.AssertErrorT(t)
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    obj := GenerateKey(curve)

    assertError(obj.Error(), "PrivateKeyD")

    d := obj.GetPrivateKeyString()

    assertNotEmpty(d, "PrivateKeyD")

    xk := New().SetCurve(curve).FromPrivateKeyString(d)

    assertError(xk.Error(), "PrivateKeyD-xk")

    assertEqual(xk.GetPrivateKey(), obj.GetPrivateKey(), "Test_GenKey-xk")
}
