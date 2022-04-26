package jwt

import (
    "errors"

    "github.com/golang-jwt/jwt/v4"
)

// 解析 token
func (this *JWT) ParseToken(strToken string) (*Token, error) {
    var err error
    var secret interface{}

    // 判断类型
    switch this.SigningMethod {
        // Hmac
        case "HS256", "HS384", "HS512":
            // 密码
            hmacSecret := this.Secret
            if hmacSecret == "" {
                err = errors.New("Hmac 密码错误或者为空")
                return nil, err
            }

            secret = []byte(hmacSecret)

        // RSA
        case "RS256", "RS384", "RS512":
            // 公钥
            keyByte := this.PublicKey
            if len(keyByte) == 0 {
                err = errors.New("RSA 公钥内容不能为空")
                return nil, err
            }

            secret, err = jwt.ParseRSAPublicKeyFromPEM(keyByte)
            if err != nil {
                return nil, err
            }

        // PSS
        case "PS256", "PS384", "PS512":
            // 公钥
            keyByte := this.PublicKey
            if len(keyByte) == 0 {
                err = errors.New("PSS 公钥内容不能为空")
                return nil, err
            }

            secret, err = jwt.ParseRSAPublicKeyFromPEM(keyByte)
            if err != nil {
                return nil, err
            }

        // ECDSA
        case "ES256", "ES384", "ES512":
            // 公钥
            keyByte := this.PublicKey
            if len(keyByte) == 0 {
                err = errors.New("ECDSA 公钥内容不能为空")
                return nil, err
            }

            secret, err = jwt.ParseECPublicKeyFromPEM(keyByte)
            if err != nil {
                return nil, err
            }

        // EdDSA
        case "EdDSA":
            // 公钥
            keyByte := this.PublicKey
            if len(keyByte) == 0 {
                err = errors.New("EdDSA 公钥内容不能为空")
                return nil, err
            }

            secret, err = jwt.ParseEdPublicKeyFromPEM(keyByte)
            if err != nil {
                return nil, err
            }

        // 国密 SM2
        case "GmSM2":
            // 公钥
            keyByte := this.PublicKey
            if len(keyByte) == 0 {
                err = errors.New("GmSM2 公钥内容不能为空")
                return nil, err
            }

            secret, err = ParseSM2PublicKeyFromPEM(keyByte)
            if err != nil {
                return nil, err
            }

        // 默认检查自定义解析方式
        default:
            // 检查自定义解析
            f, ok := this.ParseFuncs[this.SigningMethod]
            if !ok {
                err = errors.New("签名类型错误")
                return nil, err
            }

            secret, err = f(this)

            if err != nil {
                return nil, err
            }

    }

    token, err := jwt.Parse(strToken, func(token *Token) (interface{}, error) {
        return secret, nil
    })

    if err != nil {
        return nil, err
    }

    return token, nil
}
