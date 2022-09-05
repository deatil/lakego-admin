package rsa

import (
    "crypto/rsa"
    "crypto/x509"
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
 * Rsa 加密
 *
 * @create 2021-8-28
 * @author deatil
 */
type Rsa struct {
    // 私钥
    privateKey *rsa.PrivateKey

    // 公钥
    publicKey *rsa.PublicKey

    // [私钥/公钥]数据
    keyData []byte

    // 传入数据
    data []byte

    // 解析后的数据
    paredData []byte

    // 验证结果
    verify bool

    // 签名验证类型
    signHash string

    // 错误
    Errors []error
}
