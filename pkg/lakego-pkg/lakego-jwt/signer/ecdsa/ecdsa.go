package ecdsa

import (
    "crypto"

    "github.com/golang-jwt/jwt/v4"
)

var (
    SigningMethodES256K *jwt.SigningMethodECDSA
)

func init() {
    // ES256K
    SigningMethodES256K = &jwt.SigningMethodECDSA{"ES256K", crypto.SHA256, 32, 256}
    jwt.RegisterSigningMethod(SigningMethodES256K.Alg(), func() jwt.SigningMethod {
        return SigningMethodES256K
    })
}
