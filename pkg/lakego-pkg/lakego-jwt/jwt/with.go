package jwt

import (
    "time"
)

// (Issuer) 签发者
func (this *JWT) WithIss(iss string) *JWT {
    this.Claims["iss"] = iss
    return this
}

// (Issued At) 签发时间，unix时间戳
func (this *JWT) WithIat(iat int64) *JWT {
    this.Claims["iat"] = iat
    return this
}

// (Expiration Time) 过期时间，unix时间戳
func (this *JWT) WithExp(exp int64) *JWT {
    this.Claims["exp"] = time.Now().Add(time.Second * time.Duration(exp)).Unix()
    return this
}

// (Audience) 接收方
func (this *JWT) WithAud(aud string) *JWT {
    this.Claims["aud"] = aud
    return this
}

// (Subject) 主题
func (this *JWT) WithSub(sub string) *JWT {
    this.Claims["sub"] = sub
    return this
}

// (JWT ID) 唯一ID
func (this *JWT) WithJti(jti string) *JWT {
    this.Claims["jti"] = jti
    return this
}

// (Not Before) 不要早于这个时间
func (this *JWT) WithNbf(nbf int64) *JWT {
    this.Claims["nbf"] = time.Now().Add(time.Second * time.Duration(nbf)).Unix()
    return this
}

// 自定义载荷
func (this *JWT) WithClaim(key string, value interface{}) *JWT {
    this.Claims[key] = value
    return this
}

// 自定义 Header
func (this *JWT) WithHeader(key string, value interface{}) *JWT {
    this.Headers[key] = value
    return this
}

// 验证方式
func (this *JWT) WithSigningMethod(method string) *JWT {
    this.SigningMethod = method
    return this
}

// 密码
func (this *JWT) WithSecret(secret string) *JWT {
    this.Secret = secret
    return this
}

// 私钥
func (this *JWT) WithPrivateKey(privateKey string) *JWT {
    this.PrivateKey = privateKey
    return this
}

// 公钥
func (this *JWT) WithPublicKey(publicKey string) *JWT {
    this.PublicKey = publicKey
    return this
}

// 私钥密码
func (this *JWT) WithPrivateKeyPassword(password string) *JWT {
    this.PrivateKeyPassword = password
    return this
}
