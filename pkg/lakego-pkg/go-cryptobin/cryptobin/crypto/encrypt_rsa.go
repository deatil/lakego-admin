package crypto

import (
    cryptobin_rsa "github.com/deatil/go-cryptobin/cryptobin/rsa"
)

// RSA 公钥加密
func (this Cryptobin) RsaEncrypt() Cryptobin {
    rsa := cryptobin_rsa.NewRsa().
        FromPublicKey(this.key).
        FromBytes(this.data).
        Encrypt()
    if len(rsa.Errors) > 0 {
        return this.AppendError(rsa.Errors...)
    }

    this.parsedData = rsa.ToBytes()

    return this
}

// RSA 私钥解密
// pkcs8 带密码不支持其他工具生成的密钥
func (this Cryptobin) RsaDecrypt(password ...string) Cryptobin {
    rsa := cryptobin_rsa.NewRsa()

    if len(password) > 0 {
        rsa = rsa.FromPrivateKeyWithPassword(this.key, password[0])
    } else {
        rsa = rsa.FromPrivateKey(this.key)
    }

    rsa = rsa.
        FromBytes(this.data).
        Decrypt()
    if len(rsa.Errors) > 0 {
        return this.AppendError(rsa.Errors...)
    }

    this.parsedData = rsa.ToBytes()

    return this
}

// ====================

// RSA 私钥加密
// pkcs8 带密码不支持其他工具生成的密钥
func (this Cryptobin) RsaPrikeyEncrypt(password ...string) Cryptobin {
    rsa := cryptobin_rsa.NewRsa()

    if len(password) > 0 {
        rsa = rsa.FromPrivateKeyWithPassword(this.key, password[0])
    } else {
        rsa = rsa.FromPrivateKey(this.key)
    }

    rsa = rsa.
        FromBytes(this.data).
        PriKeyEncrypt()
    if len(rsa.Errors) > 0 {
        return this.AppendError(rsa.Errors...)
    }

    this.parsedData = rsa.ToBytes()

    return this
}

// RSA 公钥解密
func (this Cryptobin) RsaPubkeyDecrypt() Cryptobin {
    rsa := cryptobin_rsa.NewRsa().
        FromPublicKey(this.key).
        FromBytes(this.data).
        PubKeyDecrypt()
    if len(rsa.Errors) > 0 {
        return this.AppendError(rsa.Errors...)
    }

    this.parsedData = rsa.ToBytes()

    return this
}

// ====================

// RSA OAEP 公钥加密
// typ 为 hash.defaultHashes 对应数据
func (this Cryptobin) RsaOAEPEncrypt(typ string) Cryptobin {
    rsa := cryptobin_rsa.NewRsa().
        FromPublicKey(this.key).
        FromBytes(this.data).
        EncryptOAEP(typ)
    if len(rsa.Errors) > 0 {
        return this.AppendError(rsa.Errors...)
    }

    this.parsedData = rsa.ToBytes()

    return this
}

// RSA OAEP 私钥解密
// pkcs8 带密码不支持其他工具生成的密钥
// typ 为 hash.defaultHashes 对应数据
func (this Cryptobin) RsaOAEPDecrypt(typ string, password ...string) Cryptobin {
    rsa := cryptobin_rsa.NewRsa()

    if len(password) > 0 {
        rsa = rsa.FromPrivateKeyWithPassword(this.key, password[0])
    } else {
        rsa = rsa.FromPrivateKey(this.key)
    }

    rsa = rsa.
        FromBytes(this.data).
        DecryptOAEP(typ)
    if len(rsa.Errors) > 0 {
        return this.AppendError(rsa.Errors...)
    }

    this.parsedData = rsa.ToBytes()

    return this
}
