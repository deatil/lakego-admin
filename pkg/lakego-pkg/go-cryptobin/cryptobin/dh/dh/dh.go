package dh

import (
    "crypto/x509"

    cryptobin_dh "github.com/deatil/go-cryptobin/dhd/dh"
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
 * dh
 *
 * @create 2022-8-7
 * @author deatil
 */
type Dh struct {
    // 私钥
    privateKey *cryptobin_dh.PrivateKey

    // 公钥
    publicKey *cryptobin_dh.PublicKey

    // [私钥/公钥]数据
    keyData []byte

    // 解析后的数据
    secretData []byte

    // 错误
    Error error
}
