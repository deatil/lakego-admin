package jwt

import (
    "errors"
    "github.com/golang-jwt/jwt/v4"
)

// SignerRS256
func SignerRS256(conf IConfig) RSA {
    return RSA{
        Config: conf,
        SigningMethod: jwt.SigningMethodRS256,
    }
}

// SignerRS384
func SignerRS384(conf IConfig) RSA {
    return RSA{
        Config: conf,
        SigningMethod: jwt.SigningMethodRS384,
    }
}

// SignerRS512
func SignerRS512(conf IConfig) RSA {
    return RSA{
        Config: conf,
        SigningMethod: jwt.SigningMethodRS512,
    }
}

// SignerPS256
func SignerPS256(conf IConfig) RSA {
    return RSA{
        Config: conf,
        SigningMethod: jwt.SigningMethodPS256,
    }
}

// SignerPS384
func SignerPS384(conf IConfig) RSA {
    return RSA{
        Config: conf,
        SigningMethod: jwt.SigningMethodPS384,
    }
}

// SignerPS512
func SignerPS512(conf IConfig) RSA {
    return RSA{
        Config: conf,
        SigningMethod: jwt.SigningMethodPS512,
    }
}

func init() {
    AddSigner("RS256", func(conf IConfig) ISigner {
        return SignerRS256(conf)
    })
    AddSigner("RS384", func(conf IConfig) ISigner {
        return SignerRS384(conf)
    })
    AddSigner("RS512", func(conf IConfig) ISigner {
        return SignerRS512(conf)
    })

    AddSigner("PS256", func(conf IConfig) ISigner {
        return SignerPS256(conf)
    })
    AddSigner("PS384", func(conf IConfig) ISigner {
        return SignerPS384(conf)
    })
    AddSigner("PS512", func(conf IConfig) ISigner {
        return SignerPS512(conf)
    })
}

/**
 * RSA
 *
 * @create 2023-2-5
 * @author deatil
 */
type RSA struct {
    // 配置
    Config IConfig

    // 签名
    SigningMethod jwt.SigningMethod
}

// 获取签名
func (this RSA) GetSigner() jwt.SigningMethod {
    return this.SigningMethod
}

// 签名密钥
func (this RSA) GetSignSecrect() (secret any, err error) {
    // 获取秘钥数据
    keyByte := this.Config.PrivateKey()
    if len(keyByte) == 0 {
        err = errors.New("RSA PrivateKey empty")
        return
    }

    password := this.Config.PrivateKeyPassword()

    if password != "" {
        secret, err = jwt.ParseRSAPrivateKeyFromPEMWithPassword(keyByte, password)
    } else {
        secret, err = jwt.ParseRSAPrivateKeyFromPEM(keyByte)
    }

    return
}

// 验证密钥
func (this RSA) GetVerifySecrect() (secret any, err error) {
    // 公钥
    keyByte := this.Config.PublicKey()
    if len(keyByte) == 0 {
        err = errors.New("RSA PublicKey empty")
        return nil, err
    }

    secret, err = jwt.ParseRSAPublicKeyFromPEM(keyByte)
    return
}
