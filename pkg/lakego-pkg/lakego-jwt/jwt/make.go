package jwt

import (
    "time"
    "errors"

    "github.com/golang-jwt/jwt/v4"
)

// 生成token
func (this *JWT) MakeToken() (token string, err error) {
    var signingMethod jwt.SigningMethod
    if method, ok := this.SigningMethods[this.SigningMethod]; ok {
        signingMethod = method
    } else {
        signingMethod = jwt.SigningMethodHS256
    }

    // 签发时间没设置时重新设置
    if this.Claims["iat"] == "" {
        this.Claims["iat"] = time.Now().Unix()
    }

    // 载荷
    claims := make(jwt.MapClaims)
    if len(this.Claims) > 0 {
        for k, v := range this.Claims {
            claims[k] = v
        }
    }

    jwtToken := jwt.NewWithClaims(signingMethod, claims)

    // 设置自定义 Header
    if len(this.Headers) > 0 {
        for k2, v2 := range this.Headers {
            jwtToken.Header[k2] = v2
        }
    }

    // 密码
    var secret interface{}

    // 判断类型
    switch this.SigningMethod {
        // Hmac
        case "HS256", "HS384", "HS512":
            // 密码
            hmacSecret := this.Secret
            if hmacSecret == "" {
                err = errors.New("Hmac 密码内容不能为空")
                return
            }

            secret = []byte(hmacSecret)

        // RSA
        case "RS256", "RS384", "RS512":
            // 获取秘钥数据
            keyData := this.PrivateKey
            if keyData == "" {
                err = errors.New("RSA 私钥内容不能为空")
                return
            }

            // 转换为字节
            keyByte := []byte(keyData)

            if this.PrivateKeyPassword != "" {
                secret, err = jwt.ParseRSAPrivateKeyFromPEMWithPassword(keyByte, this.PrivateKeyPassword)
            } else {
                secret, err = jwt.ParseRSAPrivateKeyFromPEM(keyByte)
            }

            if err != nil {
                return
            }

        // PSS
        case "PS256", "PS384", "PS512":
            // 秘钥
            keyData := this.PrivateKey
            if keyData == "" {
                err = errors.New("PSS 私钥内容不能为空")
                return
            }

            // 转换为字节
            keyByte := []byte(keyData)

            secret, err = jwt.ParseRSAPrivateKeyFromPEM(keyByte)
            if err != nil {
                return
            }

        // ECDSA
        case "ES256", "ES384", "ES512":
            // 私钥
            keyData := this.PrivateKey
            if keyData == "" {
                err = errors.New("ECDSA 私钥内容不能为空")
                return
            }

            // 转换为字节
            keyByte := []byte(keyData)

            secret, err = jwt.ParseECPrivateKeyFromPEM(keyByte)
            if err != nil {
                return
            }

        // EdDSA
        case "EdDSA":
            // 私钥
            keyData := this.PrivateKey
            if keyData == "" {
                err = errors.New("EdDSA 私钥内容不能为空")
                return
            }

            // 转换为字节
            keyByte := []byte(keyData)

            secret, err = jwt.ParseEdPrivateKeyFromPEM(keyByte)
            if err != nil {
                return
            }

        // 国密 SM2
        case "GmSM2":
            // 私钥
            keyData := this.PrivateKey
            if keyData == "" {
                err = errors.New("GmSM2 私钥内容不能为空")
                return
            }

            // 转换为字节
            keyByte := []byte(keyData)

            if this.PrivateKeyPassword != "" {
                secret, err = ParseSM2PrivateKeyFromPEMWithPassword(keyByte, this.PrivateKeyPassword)
            } else {
                secret, err = ParseSM2PrivateKeyFromPEM(keyByte)
            }

            if err != nil {
                return
            }

        // 默认先检查自定义签名方式
        default:
            // 检查自定义签名
            f, ok := this.SigningFuncs[this.SigningMethod]
            if !ok {
                err = errors.New("签名类型错误")
                return
            }

            secret, err = f(this)
            if err != nil {
                return
            }

    }

    token, err = jwtToken.SignedString(secret)
    return
}
