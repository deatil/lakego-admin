package interfaces

import(
    "github.com/golang-jwt/jwt/v4"
)

/**
 * 签名接口
 *
 * @create 2023-2-5
 * @author deatil
 */
type Signer interface {
    // 获取签名
    GetSigner() jwt.SigningMethod

    // 签名密钥
    GetSignSecrect() (any, error)

    // 验证密钥
    GetVerifySecrect() (any, error)
}
