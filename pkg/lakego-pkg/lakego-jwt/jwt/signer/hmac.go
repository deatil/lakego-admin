package signer

import (
    "errors"
    "github.com/golang-jwt/jwt/v4"

    "github.com/deatil/lakego-jwt/jwt/config"
    "github.com/deatil/lakego-jwt/jwt/interfaces"
)

// SignerHS256
func SignerHS256(conf config.SignerConfig) interfaces.Signer {
    return Hmac{
        Config: conf,
        SigningMethod: jwt.SigningMethodHS256,
    }
}

// SignerHS384
func SignerHS384(conf config.SignerConfig) interfaces.Signer {
    return Hmac{
        Config: conf,
        SigningMethod: jwt.SigningMethodHS384,
    }
}

// SignerHS512
func SignerHS512(conf config.SignerConfig) interfaces.Signer {
    return Hmac{
        Config: conf,
        SigningMethod: jwt.SigningMethodHS512,
    }
}

/**
 * Hmac
 *
 * @create 2023-2-5
 * @author deatil
 */
type Hmac struct {
    // 配置
    Config config.SignerConfig

    // 签名
    SigningMethod jwt.SigningMethod
}

// 获取签名
func (this Hmac) GetSigner() jwt.SigningMethod {
    return this.SigningMethod
}

// 签名密钥
func (this Hmac) GetSignSecrect() (secret any, err error) {
    // 密码
    hmacSecret := this.Config.Secret
    if hmacSecret == "" {
        err = errors.New("Hmac 密码内容不能为空")
        return
    }

    secret = []byte(hmacSecret)
    return
}

// 验证密钥
func (this Hmac) GetVerifySecrect() (secret any, err error) {
    // 密码
    hmacSecret := this.Config.Secret
    if hmacSecret == "" {
        err = errors.New("Hmac 密码内容不能为空")
        return
    }

    secret = []byte(hmacSecret)
    return
}
