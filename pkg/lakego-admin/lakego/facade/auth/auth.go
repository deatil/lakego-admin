package auth

import (
    "sync"

    "github.com/deatil/lakego-admin/lakego/jwt"
    "github.com/deatil/lakego-admin/lakego/auth"
    "github.com/deatil/lakego-admin/lakego/facade/config"
)

var instance *auth.Auth
var once sync.Once

/**
 * Auth
 *
 * @create 2021-9-25
 * @author deatil
 */
func New() *auth.Auth {
    once.Do(func() {
        instance = auth.
            New().
            WithJWT(jwt.New())
    })

    passportConf := config.New("auth").GetStringMap("Passport")
    jwtConf := config.New("auth").GetStringMap("Jwt")

    return instance.
        WithConfig("passport", passportConf).
        WithConfig("jwt", jwtConf)
}

// 默认带接收方
func NewWithAud(aud string) *auth.Auth {
    return New().WithClaim("aud", aud)
}


