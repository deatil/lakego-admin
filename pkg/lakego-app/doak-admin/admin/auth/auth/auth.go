package auth

import (
    "github.com/deatil/lakego-jwt/jwt"
    "github.com/deatil/lakego-doak/lakego/facade/config"

    "github.com/deatil/lakego-doak-admin/admin/auth/token"
)

/**
 * Auth
 *
 * @create 2021-9-25
 * @author deatil
 */
func New() *token.Token {
    newAuth := token.New(jwt.New())

    jwtConf := config.New("auth").GetStringMap("jwt")
    passportConf := config.New("auth").GetStringMap("passport")

    return newAuth.
        SetConfig("passport", passportConf).
        SetConfig("jwt", jwtConf)
}

// 默认带接收方
func NewWithAud(aud string) *token.Token {
    return New().WithClaim("aud", aud)
}


