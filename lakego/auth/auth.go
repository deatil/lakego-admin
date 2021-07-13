package auth

import (
    "github.com/gin-gonic/gin"
    "github.com/dgrijalva/jwt-go"

    jwter "lakego-admin/lakego/jwt"
    "lakego-admin/lakego/config"
    "lakego-admin/lakego/helper"
    "lakego-admin/lakego/support/hash"
    "lakego-admin/lakego/support/base64"
    "lakego-admin/lakego/support/aes/cbc"
)

/**
 * 授权结构体
 *
 * @create 2021-6-19
 * @author deatil
 */
type Auth struct {
    ctx *gin.Context
}

func New(context *gin.Context) *Auth {
    return &Auth{
        ctx: context,
    }
}

/**
 * 获取鉴权 token 过期时间
 */
func (auth *Auth) GetAccessExpiresIn() int {
    time := config.New("auth").GetInt("Passport.AccessExpiresIn")
    return time
}

/**
 * 获取刷新 token 过期时间
 */
func (auth *Auth) GetRefreshExpiresIn() int {
    time := config.New("auth").GetInt("Passport.RefreshExpiresIn")
    return time
}

/**
 * 生成鉴权 token
 */
func (auth *Auth) MakeJWT() *jwter.JWT {
    conf := config.New("auth")

    aud := hash.MD5(helper.GetRequestIp(auth.ctx) + helper.GetHeaderByName(auth.ctx, "HTTP_USER_AGENT"))
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

    return jwter.New().
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
}


/**
 * 生成鉴权 token
 */
func (auth *Auth) MakeAccessToken(claims map[string]string) (token string, err error) {
    conf := config.New("auth")

    jti := conf.GetString("Passport.AccessTokenId")
    exp := auth.GetAccessExpiresIn()

    exp2 := int64(exp)

    passphrase := conf.GetString("Jwt.Passphrase")
    passphrase = base64.Decode(passphrase)

    jwtHandle := auth.
        MakeJWT().
        WithExp(exp2).
        WithJti(jti)

    for k, v := range claims {
        v = cbc.Encode(v, passphrase)

        jwtHandle.WithClaim(k, v)
    }

    token, err = jwtHandle.MakeToken()

    return
}

/**
 * 生成刷新 token
 */
func (auth *Auth) MakeRefreshToken(claims map[string]string) (token string, err error) {
    conf := config.New("auth")

    jti := conf.GetString("Passport.RefreshTokenId")
    exp := auth.GetRefreshExpiresIn()

    exp2 := int64(exp)

    passphrase := conf.GetString("Jwt.Passphrase")
    passphrase = base64.Decode(passphrase)

    jwtHandle := auth.
        MakeJWT().
        WithExp(exp2).
        WithJti(jti)

    for k, v := range claims {
        v = cbc.Encode(v, passphrase)

        jwtHandle.WithClaim(k, v)
    }

    token, err = jwtHandle.MakeToken()

    return
}

/**
 * 获取鉴权 token
 */
func (auth *Auth) GetAccessTokenClaims(token string) (claims jwt.MapClaims, err error) {
    jti := config.New("auth").GetString("Passport.AccessTokenId")

    claims, err = auth.MakeJWT().WithJti(jti).ParseToken(token)

    return
}

/**
 * 获取刷新 token
 */
func (auth *Auth) GetRefreshTokenClaims(token string) (claims jwt.MapClaims, err error) {
    jti := config.New("auth").GetString("Passport.RefreshTokenId")

    claims, err = auth.MakeJWT().WithJti(jti).ParseToken(token)

    return
}

/**
 * 获取鉴权 token 所在 userid
 */
func (auth *Auth) GetAccessTokenData(token string, key string) string {
    claims, err := auth.GetAccessTokenClaims(token)
    if err != nil {
        return ""
    }

    data := auth.GetDataFromTokenClaims(claims, key)

    return data
}

/**
 * 获取刷新 token 所在 userid
 */
func (auth *Auth) GetRefreshTokenData(token string, key string) string {
    claims, err := auth.GetRefreshTokenClaims(token)
    if err != nil {
        return ""
    }

    data := auth.GetDataFromTokenClaims(claims, key)

    return data

}

/**
 * 从 Claims 获取数据
 */
func (auth *Auth) GetFromTokenClaims(claims jwt.MapClaims, key string) interface{} {
    return claims[key]
}

/**
 * 从 TokenClaims 获取数据
 */
func (auth *Auth) GetDataFromTokenClaims(claims jwt.MapClaims, key string) string {
    data := claims[key].(string)

    passphrase := config.New("auth").GetString("Jwt.Passphrase")
    passphrase = base64.Decode(passphrase)

    data = cbc.Decode(data, passphrase)

    return data
}

