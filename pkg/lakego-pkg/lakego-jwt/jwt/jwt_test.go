package jwt

import (
    "time"
    "reflect"
    "testing"
)

func assertEqual(t *testing.T, actual any, expected any, msg string) {
    if !reflect.DeepEqual(actual, expected) {
        t.Errorf("Failed %s: actual: %v, expected: %v", msg, actual, expected)
    }
}

func assertNotEqual(t *testing.T, actual any, expected any, msg string) {
    if reflect.DeepEqual(actual, expected) {
        t.Errorf("Failed %s: actual: %v, expected: %v", msg, actual, expected)
    }
}

func Test_Map(t *testing.T) {
    maps := map[string]any{
        "test1": "data1",
        "test2": "data2",
        "test3": 123,
    }

    if _, ok := maps["test55"]; ok {
        t.Error("should error")
    }

    if _, ok := maps["test55"].(string); ok {
        t.Error("string should error")
    }
    if _, ok := maps["test1"].(string); !ok {
        t.Error("test1 string should not error")
    }

    if maps["test2"] == "" {
        t.Error("should not empty")
    }

    if maps["test3"] == "" {
        t.Error("should not empty")
    }
}

func Test_MakeToken(t *testing.T) {
    aud := "aud test"
    nowTime := time.Now().Unix()
    exp := time.Now().AddDate(0, 6, 0).Unix()
    iss := "iss-user"
    jti := "jti-uuid"
    nbf := int64(0)
    sub := "sub title"
    signingMethod := "HS256"
    secret := "123456654321"
    privateKeyData := []byte("")
    publicKeyData := []byte("")
    privateKeyPassword := ""

    k1 := "jwtkey"
    v1 := "jwtvalue"

    jwter := New().
        WithAud(aud).
        WithIat(nowTime).
        WithExp(exp).
        WithJti(jti).
        WithIss(iss).
        WithNbf(nbf).
        WithSub(sub).
        WithSigningMethod(signingMethod).
        WithSecret(secret).
        WithPrivateKey(privateKeyData).
        WithPublicKey(publicKeyData).
        WithPrivateKeyPassword(privateKeyPassword).
        WithClaim(k1, v1)

    token, err := jwter.MakeToken()
    if err != nil {
        t.Error("MakeToken fail")
    }

    // 解析 token
    parsedToken, err := jwter.ParseToken(token)
    if err != nil {
        t.Fatal(err)
    }

    // 验证数据
    ok, _ := jwter.Validate(parsedToken)
    if !ok {
        t.Error("Validate fail")
    }

    // 验证是否过期相关
    ok, _ = jwter.Verify(parsedToken)
    if !ok {
        t.Error("Verify fail")
    }

    claims, err := New().GetClaimsFromToken(parsedToken)
    if err != nil {
        t.Error("GetClaimsFromToken error")
    }

    if len(claims) == 0 {
        t.Error("get claims fail")
    }

    if claims[k1] == "" {
        t.Error("get claims k1 fail")
    }

    claim := claims[k1].(string)
    assertEqual(t, claim, v1, "get claims k1")

}
