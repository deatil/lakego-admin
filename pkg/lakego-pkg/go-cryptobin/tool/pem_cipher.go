package tool

import (
    "errors"
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

// 获取加密方式
func GetPEMCipher(name string) (x509.PEMCipher, error) {
    if cipher, ok := PEMCiphers[name]; ok {
        return cipher, nil
    }

    return 0, errors.New("The PEMCipher [" + name + "] is not support")
}
