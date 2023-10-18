package sm2

import (
    "testing"
    "encoding/base64"

    cryptobin_test "github.com/deatil/go-cryptobin/tool/test"
)

// signedData = S4vhrJoHXn98ByNw73CSOCqguYeuc4LrhsIHqkv/xA8Waw7YOLsfQzOKzxAjF0vyPKKSEQpq4zEgj9Mb/VL1pQ==
func Test_SM2_SignHex(t *testing.T) {
    assertError := cryptobin_test.AssertErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    uid := "N002462434000000"

    sm2key := "NBtl7WnuUtA2v5FaebEkU0/Jj1IodLGT6lQqwkzmd2E="
    sm2keyBytes, err2 := base64.StdEncoding.DecodeString(sm2key)

    assertError(err2, "sm2keyDecode")

    data := "123123"

    signedData := NewSM2().
        FromString(data).
        FromPrivateKeyBytes(sm2keyBytes).
        SignHex([]byte(uid)).
        ToBase64String()

    assertNotEmpty(signedData, "sm2-SignHex")
}

func Test_SM2_VerifyHex(t *testing.T) {
    assertError := cryptobin_test.AssertErrorT(t)
    assertBool := cryptobin_test.AssertBoolT(t)

    uid := "N002462434000000"

    sm2key := "NBtl7WnuUtA2v5FaebEkU0/Jj1IodLGT6lQqwkzmd2E="
    sm2keyBytes, err2 := base64.StdEncoding.DecodeString(sm2key)

    assertError(err2, "sm2keyDecode")

    data := "123123"
    signedData := "S4vhrJoHXn98ByNw73CSOCqguYeuc4LrhsIHqkv/xA8Waw7YOLsfQzOKzxAjF0vyPKKSEQpq4zEgj9Mb/VL1pQ=="

    verify := NewSM2().
        FromBase64String(signedData).
        FromPrivateKeyBytes(sm2keyBytes).
        MakePublicKey().
        VerifyHex([]byte(data), []byte(uid))

    assertError(verify.Error(), "sm2VerifyError")
    assertBool(verify.ToVerify(), "sm2-VerifyHex")
}

func Test_SM2_Encrypt(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)

    sm2key := "NBtl7WnuUtA2v5FaebEkU0/Jj1IodLGT6lQqwkzmd2E="
    sm2keyBytes, err2 := base64.StdEncoding.DecodeString(sm2key)
    if err2 != nil {
        t.Errorf("Failed %s, error: %+v", "sm2keyDecode", err2)
    }

    data := "test-pass"

    sm2 := NewSM2()

    enData := NewSM2().
        FromString(data).
        FromPrivateKeyBytes(sm2keyBytes).
        MakePublicKey().
        SetMode("C1C2C3"). // C1C3C2 | C1C2C3
        Encrypt().
        ToBase64String()

    deData := sm2.
        FromBase64String(enData).
        FromPrivateKeyBytes(sm2keyBytes).
        SetMode("C1C2C3"). // C1C3C2 | C1C2C3
        Decrypt().
        ToString()

    assertEqual(data, deData, "Encrypt-Dedata")
}

var (
    prikeyPKCS1 = `
-----BEGIN SM2 PRIVATE KEY-----
MHcCAQEEIAVunzkO+VYC1MFl3TfjjEHkc21eRBz+qRxbgEA6BP/FoAoGCCqBHM9V
AYItoUQDQgAEAnfcXztAc2zQ+uHuRlXuMohDdsncWxQFjrpxv5Ae3/PgH9vewt4A
oEvRqcwOBWtAXNDP6E74e5ocagfMUbq4hQ==
-----END SM2 PRIVATE KEY-----

    `
    pubkeyPKCS1 = `
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEAnfcXztAc2zQ+uHuRlXuMohDdsnc
WxQFjrpxv5Ae3/PgH9vewt4AoEvRqcwOBWtAXNDP6E74e5ocagfMUbq4hQ==
-----END PUBLIC KEY-----

    `
)

func Test_PKCS1Sign(t *testing.T) {
    assertBool := cryptobin_test.AssertBoolT(t)
    assertError := cryptobin_test.AssertErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    data := "test-pass"

    // 签名
    objSign := New().
        FromString(data).
        FromPKCS1PrivateKey([]byte(prikeyPKCS1)).
        Sign()
    signed := objSign.ToBase64String()

    assertError(objSign.Error(), "PKCS1Sign-Sign")
    assertNotEmpty(signed, "PKCS1Sign-Sign")

    // 验证
    objVerify := New().
        FromBase64String(signed).
        FromPublicKey([]byte(pubkeyPKCS1)).
        Verify([]byte(data))

    assertError(objVerify.Error(), "PKCS1Sign-Verify")
    assertBool(objVerify.ToVerify(), "PKCS1Sign-Verify")
}

func Test_PKCS1Encrypt(t *testing.T) {
    assertEqual := cryptobin_test.AssertEqualT(t)
    assertError := cryptobin_test.AssertErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    data := "123tesfd!df"

    objEn := New().
        FromString(data).
        FromPublicKey([]byte(pubkeyPKCS1)).
        Encrypt()
    enData := objEn.ToBase64String()

    assertError(objEn.Error(), "PKCS1Encrypt-Encrypt")
    assertNotEmpty(enData, "PKCS1Encrypt-Encrypt")

    objDe := New().
        FromBase64String(enData).
        FromPKCS1PrivateKey([]byte(prikeyPKCS1)).
        Decrypt()
    deData := objDe.ToString()

    assertError(objDe.Error(), "PKCS1Encrypt-Decrypt")
    assertNotEmpty(deData, "PKCS1Encrypt-Decrypt")

    assertEqual(data, deData, "PKCS1Encrypt-Dedata")
}

var (
    testSM2PublicKeyX  = "a4b75c4c8c44d11687bdd93c0883e630c895234beb685910efbe27009ad911fa"
    testSM2PublicKeyY  = "d521f5e8249de7a405f254a9888cbb8e651fd60c50bd22bd182a4bc7d1261c94"
    testSM2PrivateKeyD = "0f495b5445eb59ddecf0626f5ca0041c550584f0189e89d95f8d4c52499ff838"
)

func Test_CreateKey(t *testing.T) {
    assertError := cryptobin_test.AssertErrorT(t)
    assertNotEmpty := cryptobin_test.AssertNotEmptyT(t)

    pub := New().
        FromPublicKeyXYString(testSM2PublicKeyX, testSM2PublicKeyY).
        CreatePublicKey()
    pubData := pub.ToKeyString()

    assertError(pub.Error(), "CreateKey-pub")
    assertNotEmpty(pubData, "CreateKey-pub")

    // ======

    pri := New().
        FromPrivateKeyString(testSM2PrivateKeyD).
        CreatePrivateKey()
    priData := pri.ToKeyString()

    assertError(pri.Error(), "CreateKey-pri")
    assertNotEmpty(priData, "CreateKey-pri")
}
