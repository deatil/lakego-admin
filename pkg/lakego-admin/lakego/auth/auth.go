package auth

import (
    "github.com/golang-jwt/jwt/v4"

    jwter "github.com/deatil/lakego-admin/lakego/jwt"
    "github.com/deatil/lakego-admin/lakego/facade/config"
    "github.com/deatil/lakego-admin/lakego/support/base64"
    "github.com/deatil/lakego-admin/lakego/support/aes/cbc"
)

// 授权结构体
func New() *Auth {
    claim := make(map[string]interface{})

    return &Auth{
        claims: claim,
    }
}

/**
 * 授权
 *
 * @create 2021-6-19
 * @author deatil
 */
type Auth struct {
    // 载荷
    claims map[string]interface{}
}

/**
 * 获取鉴权 token 过期时间
 */
func (this *Auth) GetAccessExpiresIn() int {
    time := config.New("auth").GetInt("Passport.AccessExpiresIn")
    return time
}

/**
 * 获取刷新 token 过期时间
 */
func (this *Auth) GetRefreshExpiresIn() int {
    time := config.New("auth").GetInt("Passport.RefreshExpiresIn")
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
    conf := config.New("auth")

    aud := conf.GetString("Jwt.Aud")
    iss := conf.GetString("Jwt.Iss")
    sub := conf.GetString("Jwt.Sub")
    jti := conf.GetString("Jwt.Jti")
    exp := conf.GetInt("Jwt.Exp")
    nbf := conf.GetInt("Jwt.Nbf")

    signingMethod := conf.GetString("Jwt.SigningMethod")
    secret := conf.GetString("Jwt.Secret")
    privateKey := conf.GetString("Jwt.PrivateKey")
    publicKey := conf.GetString("Jwt.PublicKey")
    privateKeyPassword := conf.GetString("Jwt.PrivateKeyPassword")

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
    conf := config.New("auth")

    jti := conf.GetString("Passport.AccessTokenId")
    exp := this.GetAccessExpiresIn()

    exp2 := int64(exp)

    passphrase := conf.GetString("Jwt.Passphrase")
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
    conf := config.New("auth")

    jti := conf.GetString("Passport.RefreshTokenId")
    exp := this.GetRefreshExpiresIn()

    exp2 := int64(exp)

    passphrase := conf.GetString("Jwt.Passphrase")
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
    jti := config.New("auth").GetString("Passport.AccessTokenId")

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
    jti := config.New("auth").GetString("Passport.RefreshTokenId")

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

    passphrase := config.New("auth").GetString("Jwt.Passphrase")
    passphrase = base64.Decode(passphrase)

    if passphrase != "" {
        data = cbc.Decode(data, passphrase)
    }

    return data
}

