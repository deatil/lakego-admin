package jwt

import (
    "time"
    "errors"

    "github.com/golang-jwt/jwt/v4"
)

// 生成token
func (this *JWT) MakeToken() (token string, err error) {
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

    signer := GetSigner(this.SigningMethod)
    if signer == nil {
        err = errors.New("签名类型错误")
        return
    }

    newSigner := signer(NewConfig(
        this.Secret,
        this.PrivateKey,
        this.PublicKey,
        this.PrivateKeyPassword,
    ))

    jwtToken := jwt.NewWithClaims(newSigner.GetSigner(), claims)

    // 设置自定义 Header
    if len(this.Headers) > 0 {
        for kk, vv := range this.Headers {
            jwtToken.Header[kk] = vv
        }
    }

    // 密码
    var secret any

    secret, err = newSigner.GetSignSecrect()
    if err != nil {
        return
    }

    token, err = jwtToken.SignedString(secret)
    return
}
