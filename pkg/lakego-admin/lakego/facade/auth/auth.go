package auth

import (
    "github.com/deatil/lakego-admin/lakego/auth"
    "github.com/deatil/lakego-admin/lakego/facade/config"
)

/**
 * Auth
 *
 * @create 2021-9-25
 * @author deatil
 */
func New() *auth.Auth {
    passportConf := config.New("auth").GetStringMap("Passport")
    jwtConf := config.New("auth").GetStringMap("Jwt")

    return auth.New().
        WithConfig("passport", passportConf).
        WithConfig("jwt", jwtConf)
}

// 默认带接收方
func NewWithAud(aud string) *auth.Auth {
    passportConf := config.New("auth").GetStringMap("Passport")
    jwtConf := config.New("auth").GetStringMap("Jwt")

    return auth.New().
        WithConfig("passport", passportConf).
        WithConfig("jwt", jwtConf).
        WithClaim("aud", aud)
}


