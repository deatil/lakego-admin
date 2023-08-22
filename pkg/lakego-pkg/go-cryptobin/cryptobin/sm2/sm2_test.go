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
