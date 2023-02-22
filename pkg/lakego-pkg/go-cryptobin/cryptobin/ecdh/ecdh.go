package ecdh

import (
    "crypto/ecdh"
)

/**
 * ecdh
 * go 最低版本需要 `1.20rc1`。
 *
 * @create 2022-8-7
 * @author deatil
 */
type Ecdh struct {
    // 私钥
    privateKey *ecdh.PrivateKey

    // 公钥
    publicKey *ecdh.PublicKey

    // 散列方式
    curve ecdh.Curve

    // [私钥/公钥]数据
    keyData []byte

    // 密码数据
    secretData []byte

    // 错误
    Errors []error
}
