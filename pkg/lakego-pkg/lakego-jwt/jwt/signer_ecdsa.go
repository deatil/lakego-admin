package jwt

import (
    "errors"
    "github.com/golang-jwt/jwt/v4"
)

// SignerES256
func SignerES256(conf IConfig) ECDSA {
    return ECDSA{
        Config: conf,
        SigningMethod: jwt.SigningMethodES256,
    }
}

// SignerES384
func SignerES384(conf IConfig) ECDSA {
    return ECDSA{
        Config: conf,
        SigningMethod: jwt.SigningMethodES384,
    }
}

// SignerES512
func SignerES512(conf IConfig) ECDSA {
    return ECDSA{
        Config: conf,
        SigningMethod: jwt.SigningMethodES512,
    }
}

func init() {
    AddSigner("ES256", func(conf IConfig) ISigner {
        return SignerES256(conf)
    })
    AddSigner("ES384", func(conf IConfig) ISigner {
        return SignerES384(conf)
    })
    AddSigner("ES512", func(conf IConfig) ISigner {
        return SignerES512(conf)
    })
}

/**
 * ECDSA
 *
 * @create 2023-2-5
 * @author deatil
 */
type ECDSA struct {
    // 配置
    Config IConfig

    // 签名
    SigningMethod jwt.SigningMethod
}

// 获取签名
func (this ECDSA) GetSigner() jwt.SigningMethod {
    return this.SigningMethod
}

// 签名密钥
func (this ECDSA) GetSignSecrect() (secret any, err error) {
    // 私钥
    keyByte := this.Config.PrivateKey()
    if len(keyByte) == 0 {
        err = errors.New("ECDSA PrivateKey empty")
        return
    }

    secret, err = jwt.ParseECPrivateKeyFromPEM(keyByte)
    return
}

// 验证密钥
func (this ECDSA) GetVerifySecrect() (secret any, err error) {
    // 公钥
    keyByte := this.Config.PublicKey()
    if len(keyByte) == 0 {
        err = errors.New("ECDSA PublicKey empty")
        return nil, err
    }

    secret, err = jwt.ParseECPublicKeyFromPEM(keyByte)
    return
}
