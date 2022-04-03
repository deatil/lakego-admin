package cryptobin

// 公钥加密
func (this Rsa) Encrypt() Rsa {
    this.paredData, this.Error = pubKeyByte(this.publicKey, this.data, true)

    return this
}

// 私钥解密
func (this Rsa) Decrypt() Rsa {
    this.paredData, this.Error = priKeyByte(this.privateKey, this.data, false)

    return this
}

// 私钥加密
func (this Rsa) PriKeyEncrypt() Rsa {
    this.paredData, this.Error = priKeyByte(this.privateKey, this.data, true)

    return this
}

// 公钥解密
func (this Rsa) PubKeyDecrypt() Rsa {
    this.paredData, this.Error = pubKeyByte(this.publicKey, this.data, false)

    return this
}
