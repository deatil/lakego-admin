package jwt

import (
    "errors"
    "github.com/golang-jwt/jwt/v4"
)

// SignerHS256
func SignerHS256(conf IConfig) Hmac {
    return Hmac{
        Config: conf,
        SigningMethod: jwt.SigningMethodHS256,
    }
}

// SignerHS384
func SignerHS384(conf IConfig) Hmac {
    return Hmac{
        Config: conf,
        SigningMethod: jwt.SigningMethodHS384,
    }
}

// SignerHS512
func SignerHS512(conf IConfig) Hmac {
    return Hmac{
        Config: conf,
        SigningMethod: jwt.SigningMethodHS512,
    }
}

func init() {
    AddSigner("HS256", func(conf IConfig) ISigner {
        return SignerHS256(conf)
    })
    AddSigner("HS384", func(conf IConfig) ISigner {
        return SignerHS384(conf)
    })
    AddSigner("HS512", func(conf IConfig) ISigner {
        return SignerHS512(conf)
    })
}

/**
 * Hmac
 *
 * @create 2023-2-5
 * @author deatil
 */
type Hmac struct {
    // 配置
    Config IConfig

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
    hmacSecret := this.Config.Secret()
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
    hmacSecret := this.Config.Secret()
    if hmacSecret == "" {
        err = errors.New("Hmac 密码内容不能为空")
        return
    }

    secret = []byte(hmacSecret)
    return
}
