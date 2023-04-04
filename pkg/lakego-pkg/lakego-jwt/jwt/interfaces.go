package jwt

import(
    "github.com/golang-jwt/jwt/v4"
)

/**
 * 签名数据接口
 *
 * @create 2023-2-5
 * @author deatil
 */
type ISigner interface {
    // 获取签名
    GetSigner() jwt.SigningMethod

    // 签名密钥
    GetSignSecrect() (any, error)

    // 验证密钥
    GetVerifySecrect() (any, error)
}

/**
 * 配置接口
 *
 * @create 2023-4-5
 * @author deatil
 */
type IConfig interface {
    // 秘钥
    Secret() string

    // 私钥
    PrivateKey() []byte

    // 公钥
    PublicKey() []byte

    // 私钥密码
    PrivateKeyPassword() string
}
