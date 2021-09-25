package auth

import (
    "lakego-admin/lakego/auth"
)

/**
 * Auth
 *
 * @create 2021-9-25
 * @author deatil
 */
func New() *auth.Auth {
    return auth.New()
}

// 默认带接收方
func NewWithAud(aud string) *auth.Auth {
    return auth.New().WithClaim("aud", aud)
}


