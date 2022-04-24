package jwt

import (
    "github.com/golang-jwt/jwt/v4"
)

// 验证方式列表
var signingMethodList = map[string]jwt.SigningMethod {
    // Hmac
    "HS256": jwt.SigningMethodHS256,
    "HS384": jwt.SigningMethodHS384,
    "HS512": jwt.SigningMethodHS512,

    // RSA
    "RS256": jwt.SigningMethodRS256,
    "RS384": jwt.SigningMethodRS384,
    "RS512": jwt.SigningMethodRS512,

    // PSS
    "PS256": jwt.SigningMethodPS256,
    "PS384": jwt.SigningMethodPS384,
    "PS512": jwt.SigningMethodPS512,

    // ECDSA
    "ES256": jwt.SigningMethodES256,
    "ES384": jwt.SigningMethodES384,
    "ES512": jwt.SigningMethodES512,

    // EdDSA
    "EdDSA": jwt.SigningMethodEdDSA,

    // 国密 SM2
    "GmSM2": SigningMethodGmSM2,
}
