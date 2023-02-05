package signer

import (
    "errors"
    "github.com/golang-jwt/jwt/v4"

    "github.com/deatil/lakego-jwt/jwt/config"
    "github.com/deatil/lakego-jwt/jwt/interfaces"
)

// SignerRS256
func SignerRS256(conf config.SignerConfig) interfaces.Signer {
    return RSA{
        Config: conf,
        SigningMethod: jwt.SigningMethodRS256,
    }
}

// SignerRS384
func SignerRS384(conf config.SignerConfig) interfaces.Signer {
    return RSA{
        Config: conf,
        SigningMethod: jwt.SigningMethodRS384,
    }
}

// SignerRS512
func SignerRS512(conf config.SignerConfig) interfaces.Signer {
    return RSA{
        Config: conf,
        SigningMethod: jwt.SigningMethodRS512,
    }
}

// SignerPS256
func SignerPS256(conf config.SignerConfig) interfaces.Signer {
    return RSA{
        Config: conf,
        SigningMethod: jwt.SigningMethodPS256,
    }
}

// SignerPS384
func SignerPS384(conf config.SignerConfig) interfaces.Signer {
    return RSA{
        Config: conf,
        SigningMethod: jwt.SigningMethodPS384,
    }
}

// SignerPS512
func SignerPS512(conf config.SignerConfig) interfaces.Signer {
    return RSA{
        Config: conf,
        SigningMethod: jwt.SigningMethodPS512,
    }
}

/**
 * RSA
 *
 * @create 2023-2-5
 * @author deatil
 */
type RSA struct {
    // 配置
    Config config.SignerConfig

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
    keyByte := this.Config.PrivateKey
    if len(keyByte) == 0 {
        err = errors.New("RSA 私钥内容不能为空")
        return
    }

    password := this.Config.PrivateKeyPassword

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
    keyByte := this.Config.PublicKey
    if len(keyByte) == 0 {
        err = errors.New("RSA 公钥内容不能为空")
        return nil, err
    }

    secret, err = jwt.ParseRSAPublicKeyFromPEM(keyByte)
    return
}
