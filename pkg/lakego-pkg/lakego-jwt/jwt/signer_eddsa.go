package jwt

import (
    "errors"
    "github.com/golang-jwt/jwt/v4"
)

// SignerEdDSA
func SignerEdDSA(conf IConfig) EdDSA {
    return EdDSA{
        Config: conf,
        SigningMethod: jwt.SigningMethodEdDSA,
    }
}

func init() {
    AddSigner("EdDSA", func(conf IConfig) ISigner {
        return SignerEdDSA(conf)
    })
}

/**
 * EdDSA
 *
 * @create 2023-2-5
 * @author deatil
 */
type EdDSA struct {
    // 配置
    Config IConfig

    // 签名
    SigningMethod jwt.SigningMethod
}

// 获取签名
func (this EdDSA) GetSigner() jwt.SigningMethod {
    return this.SigningMethod
}

// 签名密钥
func (this EdDSA) GetSignSecrect() (secret any, err error) {
    // 私钥
    keyByte := this.Config.PrivateKey()
    if len(keyByte) == 0 {
        err = errors.New("EdDSA PublicKey empty")
        return
    }

    secret, err = jwt.ParseEdPrivateKeyFromPEM(keyByte)
    return
}

// 验证密钥
func (this EdDSA) GetVerifySecrect() (secret any, err error) {
    // 公钥
    keyByte := this.Config.PublicKey()
    if len(keyByte) == 0 {
        err = errors.New("EdDSA PublicKey empty")
        return nil, err
    }

    secret, err = jwt.ParseEdPublicKeyFromPEM(keyByte)
    return
}
