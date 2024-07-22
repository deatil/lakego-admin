package jwt

import (
    "errors"

    "github.com/golang-jwt/jwt/v4"
)

// 解析 token
func (this *JWT) ParseToken(strToken string) (*Token, error) {
    var err error
    var secret any

    signer := GetSigner(this.SigningMethod)
    if signer == nil {
        return nil, errors.New("not support signer")
    }

    newSigner := signer(NewConfig(
        this.Secret,
        this.PrivateKey,
        this.PublicKey,
        this.PrivateKeyPassword,
    ))

    secret, err = newSigner.GetVerifySecrect()
    if err != nil {
        return nil, err
    }

    token, err := jwt.Parse(strToken, func(token *Token) (any, error) {
        return secret, nil
    })

    if err != nil {
        return nil, err
    }

    return token, err
}
