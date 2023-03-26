package sm2

import (
    "fmt"
    "testing"
    "encoding/base64"
)

// signedData = S4vhrJoHXn98ByNw73CSOCqguYeuc4LrhsIHqkv/xA8Waw7YOLsfQzOKzxAjF0vyPKKSEQpq4zEgj9Mb/VL1pQ==
func Test_SM2_SignHex(t *testing.T) {
    uid := "N002462434000000"

    sm2key := "NBtl7WnuUtA2v5FaebEkU0/Jj1IodLGT6lQqwkzmd2E="
    sm2keyBytes, err2 := base64.StdEncoding.DecodeString(sm2key)
    if err2 != nil {
        t.Errorf("Failed %s, error: %+v", "sm2keyDecode", err2)
    }

    data := "123123"

    signedData := NewSM2().
        FromString(data).
        FromPrivateKeyBytes(sm2keyBytes).
        SignHex([]byte(uid)).
        ToBase64String()

    fmt.Println(signedData)
}

func Test_SM2_VerifyHex(t *testing.T) {
    uid := "N002462434000000"

    sm2key := "NBtl7WnuUtA2v5FaebEkU0/Jj1IodLGT6lQqwkzmd2E="
    sm2keyBytes, err2 := base64.StdEncoding.DecodeString(sm2key)
    if err2 != nil {
        t.Errorf("Failed %s, error: %+v", "sm2keyDecode", err2)
    }

    data := "123123"
    signedData := "S4vhrJoHXn98ByNw73CSOCqguYeuc4LrhsIHqkv/xA8Waw7YOLsfQzOKzxAjF0vyPKKSEQpq4zEgj9Mb/VL1pQ=="

    verify := NewSM2().
        FromBase64String(signedData).
        FromPrivateKeyBytes(sm2keyBytes).
        MakePublicKey().
        VerifyHex([]byte(data), []byte(uid))

    err3 := verify.Error()
    if err3 != nil {
        t.Errorf("Failed %s, error: %+v", "sm2 Verify", err3)
    }

    fmt.Println(verify.ToVerify())
}
