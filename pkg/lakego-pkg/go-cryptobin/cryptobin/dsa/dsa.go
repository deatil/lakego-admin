package dsa

import (
    "crypto/dsa"
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

    // 验证结果
    verify bool

    // 错误
    Errors []error
}
