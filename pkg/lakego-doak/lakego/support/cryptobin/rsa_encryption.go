package cryptobin

import (
    "io"
    "bytes"
    "crypto/rsa"
)

// 公钥加密
func (this *Rsa) Encrypt(input []byte, keyBytes []byte) ([]byte, error) {
    // 解析公钥
    pubkey, err := ParseRSAPublicKeyFromPEM(keyBytes)
    if err != nil {
        return nil, err
    }

    output := bytes.NewBuffer(nil)

    // 加密
    err = pubKeyIO(pubkey, bytes.NewReader(input), output, true)
    if err != nil {
        return nil, err
    }

    return io.ReadAll(output)
}

// 私钥解密
func (this *Rsa) Decrypt(input []byte, keyBytes []byte, password ...string) ([]byte, error) {
    var prikey *rsa.PrivateKey
    var err error

    if len(password) > 0 {
        prikey, err = ParseRSAPrivateKeyFromPEMWithPassword(keyBytes, password[0])
    } else {
        prikey, err = ParseRSAPrivateKeyFromPEM(keyBytes)
    }

    if err != nil {
        return nil, err
    }

    output := bytes.NewBuffer(nil)

    // 解密
    err = priKeyIO(prikey, bytes.NewReader(input), output, false)
    if err != nil {
        return nil, err
    }

    return io.ReadAll(output)
}

// 私钥加密
func (this *Rsa) PriKeyEncrypt(input []byte, keyBytes []byte, password ...string) ([]byte, error) {
    var priv *rsa.PrivateKey
    var err error

    if len(password) > 0 {
        priv, err = ParseRSAPrivateKeyFromPEMWithPassword(keyBytes, password[0])
    } else {
        priv, err = ParseRSAPrivateKeyFromPEM(keyBytes)
    }

    if err != nil {
        return nil, err
    }

    output := bytes.NewBuffer(nil)
    err = priKeyIO(priv, bytes.NewReader(input), output, true)
    if err != nil {
        return nil, err
    }

    return io.ReadAll(output)
}

// 公钥解密
func (this *Rsa) PubKeyDecrypt(input []byte, keyBytes []byte) ([]byte, error) {
    // 解析公钥
    pubkey, err := ParseRSAPublicKeyFromPEM(keyBytes)
    if err != nil {
        return nil, err
    }

    output := bytes.NewBuffer(nil)
    err = pubKeyIO(pubkey, bytes.NewReader(input), output, false)
    if err != nil {
        return nil, err
    }

    return io.ReadAll(output)
}
