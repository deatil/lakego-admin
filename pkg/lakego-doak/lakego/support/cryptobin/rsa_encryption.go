package cryptobin

import (
    "crypto/rsa"
)

// 公钥加密
func (this *Rsa) Encrypt(input []byte, keyBytes []byte) ([]byte, error) {
    // 解析公钥
    pubkey, err := this.ParseRSAPublicKeyFromPEM(keyBytes)
    if err != nil {
        return nil, err
    }

    return pubKeyByte(pubkey, input, true)
}

// 私钥解密
func (this *Rsa) Decrypt(input []byte, keyBytes []byte, password ...string) ([]byte, error) {
    var prikey *rsa.PrivateKey
    var err error

    if len(password) > 0 {
        prikey, err = this.ParseRSAPrivateKeyFromPEMWithPassword(keyBytes, password[0])
    } else {
        prikey, err = this.ParseRSAPrivateKeyFromPEM(keyBytes)
    }

    if err != nil {
        return nil, err
    }

    return priKeyByte(prikey, input, false)
}

// 私钥加密
func (this *Rsa) PriKeyEncrypt(input []byte, keyBytes []byte, password ...string) ([]byte, error) {
    var priv *rsa.PrivateKey
    var err error

    if len(password) > 0 {
        priv, err = this.ParseRSAPrivateKeyFromPEMWithPassword(keyBytes, password[0])
    } else {
        priv, err = this.ParseRSAPrivateKeyFromPEM(keyBytes)
    }

    if err != nil {
        return nil, err
    }

    return priKeyByte(priv, input, true)
}

// 公钥解密
func (this *Rsa) PubKeyDecrypt(input []byte, keyBytes []byte) ([]byte, error) {
    // 解析公钥
    pubkey, err := this.ParseRSAPublicKeyFromPEM(keyBytes)
    if err != nil {
        return nil, err
    }

    return pubKeyByte(pubkey, input, false)
}
