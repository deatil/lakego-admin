package signer

import (
    "errors"
    "github.com/golang-jwt/jwt/v4"

    "github.com/deatil/lakego-jwt/jwt/config"
    "github.com/deatil/lakego-jwt/jwt/interfaces"
)

// SignerES256
func SignerES256(conf config.SignerConfig) interfaces.Signer {
    return ECDSA{
        Config: conf,
        SigningMethod: jwt.SigningMethodES256,
    }
}

// SignerES384
func SignerES384(conf config.SignerConfig) interfaces.Signer {
    return ECDSA{
        Config: conf,
        SigningMethod: jwt.SigningMethodES384,
    }
}

// SignerES512
func SignerES512(conf config.SignerConfig) interfaces.Signer {
    return ECDSA{
        Config: conf,
        SigningMethod: jwt.SigningMethodES512,
    }
}

/**
 * ECDSA
 *
 * @create 2023-2-5
 * @author deatil
 */
type ECDSA struct {
    // 配置
    Config config.SignerConfig

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
    keyByte := this.Config.PrivateKey
    if len(keyByte) == 0 {
        err = errors.New("ECDSA 私钥内容不能为空")
        return
    }

    secret, err = jwt.ParseECPrivateKeyFromPEM(keyByte)
    return
}

// 验证密钥
func (this ECDSA) GetVerifySecrect() (secret any, err error) {
    // 公钥
    keyByte := this.Config.PublicKey
    if len(keyByte) == 0 {
        err = errors.New("ECDSA 公钥内容不能为空")
        return nil, err
    }

    secret, err = jwt.ParseECPublicKeyFromPEM(keyByte)
    return
}
