package cryptobin

// RSA 公钥加密
func (this Cryptobin) RsaEncrypt() Cryptobin {
    rsa := NewRsa().
        FromPublicKey(this.key).
        FromBytes(this.data).
        Encrypt()
    if rsa.Error != nil {
        this.Error = rsa.Error

        return this
    }

    this.parsedData = rsa.ToBytes()

    return this
}

// RSA 私钥解密
// pkcs8 带密码不支持其他工具生成的密钥
func (this Cryptobin) RsaDecrypt(password ...string) Cryptobin {
    rsa := NewRsa()

    if len(password) > 0 {
        rsa = rsa.FromPrivateKeyWithPassword(this.key, password[0])
    } else {
        rsa = rsa.FromPrivateKey(this.key)
    }

    rsa = rsa.
        FromBytes(this.data).
        Decrypt()
    if rsa.Error != nil {
        this.Error = rsa.Error

        return this
    }

    this.parsedData = rsa.ToBytes()

    return this
}

// ====================

// RSA 私钥加密
// pkcs8 带密码不支持其他工具生成的密钥
func (this Cryptobin) RsaPrikeyEncrypt(password ...string) Cryptobin {
    rsa := NewRsa()

    if len(password) > 0 {
        rsa = rsa.FromPrivateKeyWithPassword(this.key, password[0])
    } else {
        rsa = rsa.FromPrivateKey(this.key)
    }

    rsa = rsa.
        FromBytes(this.data).
        PriKeyEncrypt()
    if rsa.Error != nil {
        this.Error = rsa.Error

        return this
    }

    this.parsedData = rsa.ToBytes()

    return this
}

// RSA 公钥解密
func (this Cryptobin) RsaPubkeyDecrypt() Cryptobin {
    rsa := NewRsa().
        FromPublicKey(this.key).
        FromBytes(this.data).
        PubKeyDecrypt()
    if rsa.Error != nil {
        this.Error = rsa.Error
        return this
    }

    this.parsedData = rsa.ToBytes()

    return this
}

// ====================

// RSA OAEP 公钥加密
// typ 为 hash.defaultHashes 对应数据
func (this Cryptobin) RsaOAEPEncrypt(typ string) Cryptobin {
    rsa := NewRsa().
        FromPublicKey(this.key).
        FromBytes(this.data).
        EncryptOAEP(typ)
    if rsa.Error != nil {
        this.Error = rsa.Error

        return this
    }

    this.parsedData = rsa.ToBytes()

    return this
}

// RSA OAEP 私钥解密
// pkcs8 带密码不支持其他工具生成的密钥
// typ 为 hash.defaultHashes 对应数据
func (this Cryptobin) RsaOAEPDecrypt(typ string, password ...string) Cryptobin {
    rsa := NewRsa()

    if len(password) > 0 {
        rsa = rsa.FromPrivateKeyWithPassword(this.key, password[0])
    } else {
        rsa = rsa.FromPrivateKey(this.key)
    }

    rsa = rsa.
        FromBytes(this.data).
        DecryptOAEP(typ)
    if rsa.Error != nil {
        this.Error = rsa.Error

        return this
    }

    this.parsedData = rsa.ToBytes()

    return this
}
