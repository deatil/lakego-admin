package curve25519

import (
    cryptobin_curve25519 "github.com/deatil/go-cryptobin/dh/curve25519"
)

/**
 * curve25519
 *
 * @create 2022-8-7
 * @author deatil
 */
type Curve25519 struct {
    // 私钥
    privateKey *cryptobin_curve25519.PrivateKey

    // 公钥
    publicKey *cryptobin_curve25519.PublicKey

    // [私钥/公钥]数据
    keyData []byte

    // 密码数据
    secretData []byte

    // 错误
    Errors []error
}
