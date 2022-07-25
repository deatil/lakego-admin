package cryptobin

import (
    "crypto/dsa"
)

/**
 * DSA
 *
 * @create 2022-7-25
 * @author deatil
 */
type DSA struct {
    // 私钥
    privateKey *dsa.PrivateKey

    // 公钥
    publicKey *dsa.PublicKey

    // [私钥/公钥]数据
    keyData []byte

    // 传入数据
    data []byte

    // 解析后的数据
    paredData []byte

    // 签名验证类型
    signHash string

    // 验证后情况
    veryed bool

    // 错误
    Error error
}
