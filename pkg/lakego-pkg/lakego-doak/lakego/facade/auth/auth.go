package auth

import (
    "sync"

    "github.com/deatil/lakego-jwt/jwt"
    "github.com/deatil/lakego-doak/lakego/auth"
    "github.com/deatil/lakego-doak/lakego/facade/config"
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

    jwtConf := config.New("auth").GetStringMap("jwt")
    passportConf := config.New("auth").GetStringMap("passport")

    return instance.
        WithOneConfig("passport", passportConf).
        WithOneConfig("jwt", jwtConf)
}

// 默认带接收方
func NewWithAud(aud string) *auth.Auth {
    return New().WithClaim("aud", aud)
}


