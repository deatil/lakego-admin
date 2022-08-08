package curve25519

import (
    "crypto/x509"

    cryptobin_curve25519 "github.com/deatil/go-cryptobin/dhd/curve25519"
)

// pem 加密方式
var PEMCiphers = map[string]x509.PEMCipher{
    "DESCBC":     x509.PEMCipherDES,
    "DESEDE3CBC": x509.PEMCipher3DES,
    "AES128CBC":  x509.PEMCipherAES128,
    "AES192CBC":  x509.PEMCipherAES192,
    "AES256CBC":  x509.PEMCipherAES256,
}

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
    Error error
}
