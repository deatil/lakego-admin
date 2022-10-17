package ecdh

import (
    cryptobin_ecdh "github.com/deatil/go-cryptobin/dh/ecdh"
)

/**
 * ecdh
 *
 * @create 2022-8-7
 * @author deatil
 */
type Ecdh struct {
    // 私钥
    privateKey *cryptobin_ecdh.PrivateKey

    // 公钥
    publicKey *cryptobin_ecdh.PublicKey

    // 散列方式
    curve cryptobin_ecdh.Curve

    // [私钥/公钥]数据
    keyData []byte

    // 密码数据
    secretData []byte

    // 错误
    Errors []error
}
