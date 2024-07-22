package jwt

import(
    "time"
)

type Option func(*JWT)

// (Issuer) 签发者
func WithIss(iss string) Option {
    return func(jwt *JWT) {
        jwt.Claims["iss"] = iss
    }
}

// (Issued At) 签发时间，unix时间戳
func WithIat(iat int64) Option {
    return func(jwt *JWT) {
        jwt.Claims["iat"] = iat
    }
}

// (Expiration Time) 过期时间，unix时间戳
func WithExp(exp int64) Option {
    return func(jwt *JWT) {
        jwt.Claims["exp"] = time.Now().Add(time.Second * time.Duration(exp)).Unix()
    }
}

// (Audience) 接收方
func WithAud(aud string) Option {
    return func(jwt *JWT) {
        jwt.Claims["aud"] = aud
    }
}

// (Subject) 主题
func WithSub(sub string) Option {
    return func(jwt *JWT) {
        jwt.Claims["sub"] = sub
    }
}

// (JWT ID) 唯一ID
func WithJti(jti string) Option {
    return func(jwt *JWT) {
        jwt.Claims["jti"] = jti
    }
}

// (Not Before) 不要早于这个时间
func WithNbf(nbf int64) Option {
    return func(jwt *JWT) {
        jwt.Claims["nbf"] = time.Now().Add(time.Second * time.Duration(nbf)).Unix()
    }
}

// 自定义 Header
func WithHeader(key string, value any) Option {
    return func(jwt *JWT) {
        jwt.Headers[key] = value
    }
}

// 自定义载荷
func WithClaim(key string, value any) Option {
    return func(jwt *JWT) {
        jwt.Claims[key] = value
    }
}

// 验证方式
func WithSigningMethod(method string) Option {
    return func(jwt *JWT) {
        jwt.SigningMethod = method
    }
}

// 密码
func WithSecret(secret string) Option {
    return func(jwt *JWT) {
        jwt.Secret = secret
    }
}

// 私钥
func WithPrivateKey(privateKey []byte) Option {
    return func(jwt *JWT) {
        jwt.PrivateKey = privateKey
    }
}

// 公钥
func WithPublicKey(publicKey []byte) Option {
    return func(jwt *JWT) {
        jwt.PublicKey = publicKey
    }
}

// 私钥密码
func WithPrivateKeyPassword(password string) Option {
    return func(jwt *JWT) {
        jwt.PrivateKeyPassword = password
    }
}
