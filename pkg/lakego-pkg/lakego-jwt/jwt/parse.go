package jwt

import (
    "errors"

    "github.com/golang-jwt/jwt/v4"

    "github.com/deatil/lakego-jwt/jwt/config"
)

// 解析 token
func (this *JWT) ParseToken(strToken string) (*Token, error) {
    var err error
    var secret any

    signer := NewSigner().Get(this.SigningMethod)
    if signer == nil {
        return nil, errors.New("签名类型错误")
    }

    newSigner := signer(config.SignerConfig{
        Secret:     this.Secret,
        PrivateKey: this.PrivateKey,
        PublicKey:  this.PublicKey,
        PrivateKeyPassword: this.PrivateKeyPassword,
    })

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
