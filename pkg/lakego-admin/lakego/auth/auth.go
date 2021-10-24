package auth

import (
    "github.com/golang-jwt/jwt/v4"

    jwter "github.com/deatil/lakego-admin/lakego/jwt"
    "github.com/deatil/lakego-admin/lakego/support/base64"
    "github.com/deatil/lakego-admin/lakego/support/aes/cbc"
)

// 授权结构体
func New() *Auth {
    return &Auth{
        config: make(map[string]interface{}),
        claims: make(map[string]interface{}),
    }
}

/**
 * 授权
 *
 * @create 2021-6-19
 * @author deatil
 */
type Auth struct {
    // 配置
    config map[string]interface{}

    // 载荷
    claims map[string]interface{}
}

/**
 * 设置配置
 */
func (this *Auth) WithConfig(key string, value interface{}) *Auth {
    this.config[key] = value

    return this
}

/**
 * 批量设置配置
 */
func (this *Auth) WithConfigs(configs map[string]interface{}) *Auth {
    if len(configs) > 0 {
        for k, v := range configs {
            this.WithConfig(k, v)
        }
    }

    return this
}

/**
 * 获取配置
 */
func (this *Auth) GetConfig(key string) interface{} {
    return this.config[key]
}

/**
 * 获取配置
 */
func (this *Auth) GetConfigFromMap(key string, key2 string) interface{} {
    // 配置
    conf := this.config[key]
    if conf == "" {
        return nil
    }

    // 配置列表
    confMap := conf.(map[string]interface{})

    // 过期时间
    conf2 := confMap[key2]
    if conf2 == "" {
        return nil
    }

    return conf2
}

/**
 * 获取配置
 */
func (this *Auth) GetConfigFromMapStringDefault(key string, key2 string, defaultValue string) string {
    conf := this.GetConfigFromMap(key, key2)
    if conf == nil {
        return defaultValue
    }

    return conf.(string)
}

/**
 * 获取配置
 */
func (this *Auth) GetConfigFromMapIntDefault(key string, key2 string, defaultValue int) int {
    conf := this.GetConfigFromMap(key, key2)
    if conf == nil {
        return defaultValue
    }

    return conf.(int)
}

/**
 * 获取鉴权 token 过期时间
 */
func (this *Auth) GetAccessExpiresIn() int {
    // 过期时间
    time := this.GetConfigFromMapIntDefault("passport", "accessexpiresin", 0)

    return time
}

/**
 * 获取刷新 token 过期时间
 */
func (this *Auth) GetRefreshExpiresIn() int {
    // 过期时间
    time := this.GetConfigFromMapIntDefault("passport", "refreshexpiresin", 0)

    return time
}

// 设置自定义载荷
func (this *Auth) WithClaim(key string, value interface{}) *Auth {
    this.claims[key] = value
    return this
}

/**
 * 生成鉴权 token
 */
func (this *Auth) MakeJWT() *jwter.JWT {
    aud := this.GetConfigFromMapStringDefault("jwt", "aud", "")
    iss := this.GetConfigFromMapStringDefault("jwt", "iss", "")
    sub := this.GetConfigFromMapStringDefault("jwt", "sub", "")
    jti := this.GetConfigFromMapStringDefault("jwt", "jti", "")
    exp := this.GetConfigFromMapIntDefault("jwt", "exp", 0)
    nbf := this.GetConfigFromMapIntDefault("jwt", "nbf", 0)

    signingMethod := this.GetConfigFromMapStringDefault("jwt", "signingmethod", "")
    secret := this.GetConfigFromMapStringDefault("jwt", "secret", "")
    privateKey := this.GetConfigFromMapStringDefault("jwt", "privatekey", "")
    publicKey := this.GetConfigFromMapStringDefault("jwt", "publickey", "")
    privateKeyPassword := this.GetConfigFromMapStringDefault("jwt", "privatekeypassword", "")

    exp2 := int64(exp)
    nbf2 := int64(nbf)

    jwtHandler := jwter.New().
        WithAud(aud).
        WithExp(exp2).
        WithJti(jti).
        WithIss(iss).
        WithNbf(nbf2).
        WithSub(sub).
        WithSigningMethod(signingMethod).
        WithSecret(secret).
        WithPrivateKey(privateKey).
        WithPublicKey(publicKey).
        WithPrivateKeyPassword(privateKeyPassword)

    if len(this.claims) > 0 {
        for k, v := range this.claims {
            jwtHandler.WithClaim(k, v)
        }
    }

    return jwtHandler
}

/**
 * 生成 token
 */
func (this *Auth) MakeToken(claims map[string]string) (token string, err error) {
    jwtHandle := this.MakeJWT()

    if len(claims) > 0 {
        for k, v := range claims {
            jwtHandle.WithClaim(k, v)
        }
    }

    token, err = jwtHandle.MakeToken()

    return
}

/**
 * 生成鉴权 token
 */
func (this *Auth) MakeAccessToken(claims map[string]string) (token string, err error) {
    jti := this.GetConfigFromMapStringDefault("passport", "accesstokenid", "")
    exp := this.GetAccessExpiresIn()

    exp2 := int64(exp)

    passphrase := this.GetConfigFromMapStringDefault("jwt", "passphrase", "")
    passphrase = base64.Decode(passphrase)

    jwtHandle := this.
        MakeJWT().
        WithExp(exp2).
        WithJti(jti)

    if len(claims) > 0 {
        for k, v := range claims {
            if passphrase != "" {
                v = cbc.Encode(v, passphrase)
            }

            jwtHandle.WithClaim(k, v)
        }
    }

    token, err = jwtHandle.MakeToken()

    return
}

/**
 * 生成刷新 token
 */
func (this *Auth) MakeRefreshToken(claims map[string]string) (token string, err error) {
    jti := this.GetConfigFromMapStringDefault("passport", "refreshtokenid", "")
    exp := this.GetRefreshExpiresIn()

    exp2 := int64(exp)

    passphrase := this.GetConfigFromMapStringDefault("jwt", "passphrase", "")
    passphrase = base64.Decode(passphrase)

    jwtHandle := this.
        MakeJWT().
        WithExp(exp2).
        WithJti(jti)

    if len(claims) > 0 {
        for k, v := range claims {
            if passphrase != "" {
                v = cbc.Encode(v, passphrase)
            }

            jwtHandle.WithClaim(k, v)
        }
    }

    token, err = jwtHandle.MakeToken()

    return
}

/**
 * 获取鉴权 token
 */
func (this *Auth) GetAccessTokenClaims(token string, verify ...bool) (jwt.MapClaims, error) {
    jti := this.GetConfigFromMapStringDefault("passport", "accesstokenid", "")

    jwter := this.MakeJWT().WithJti(jti)

    parsedToken, err := jwter.ParseToken(token)
    if err != nil {
        return nil, err
    }

    _, err2 := jwter.Validate(parsedToken)
    if err2 != nil {
        return nil, err2
    }

    // 检测
    isVerify := true
    if len(verify) > 0 {
        isVerify = verify[0]
    }

    if isVerify {
        _, err3 := jwter.Verify(parsedToken)
        if err3 != nil {
            return nil, err3
        }
    }

    claims, claimsErr := jwter.GetClaimsFromToken(parsedToken)
    if claimsErr != nil {
        return nil, claimsErr
    }

    return claims, nil
}

/**
 * 获取刷新 token
 */
func (this *Auth) GetRefreshTokenClaims(token string, verify ...bool) (jwt.MapClaims, error) {
    jti := this.GetConfigFromMapStringDefault("passport", "refreshtokenid", "")

    jwter := this.MakeJWT().WithJti(jti)

    parsedToken, err := jwter.ParseToken(token)
    if err != nil {
        return nil, err
    }

    _, err2 := jwter.Validate(parsedToken)
    if err2 != nil {
        return nil, err2
    }

    // 检测
    isVerify := true
    if len(verify) > 0 {
        isVerify = verify[0]
    }

    if isVerify {
        _, err3 := jwter.Verify(parsedToken)
        if err3 != nil {
            return nil, err3
        }
    }

    claims, claimsErr := jwter.GetClaimsFromToken(parsedToken)
    if claimsErr != nil {
        return nil, claimsErr
    }

    return claims, nil
}

/**
 * 获取鉴权 token 所在 userid
 */
func (this *Auth) GetAccessTokenData(token string, key string, verify ...bool) string {
    claims, err := this.GetAccessTokenClaims(token, verify...)
    if err != nil {
        return ""
    }

    data := this.GetDataFromTokenClaims(claims, key)

    return data
}

/**
 * 获取刷新 token 所在 userid
 */
func (this *Auth) GetRefreshTokenData(token string, key string, verify ...bool) string {
    claims, err := this.GetRefreshTokenClaims(token, verify...)
    if err != nil {
        return ""
    }

    data := this.GetDataFromTokenClaims(claims, key)

    return data

}

/**
 * 从 Claims 获取数据
 */
func (this *Auth) GetFromTokenClaims(claims jwt.MapClaims, key string) interface{} {
    return claims[key]
}

/**
 * 从 TokenClaims 获取数据
 */
func (this *Auth) GetDataFromTokenClaims(claims jwt.MapClaims, key string) string {
    data := claims[key].(string)

    passphrase := this.GetConfigFromMapStringDefault("jwt", "passphrase", "")
    passphrase = base64.Decode(passphrase)

    if passphrase != "" {
        data = cbc.Decode(data, passphrase)
    }

    return data
}

