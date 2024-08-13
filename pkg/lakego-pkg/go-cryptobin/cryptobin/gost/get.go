package gost

import (
    "github.com/deatil/go-cryptobin/gost"
)

// 获取 PrivateKey
func (this Gost) GetPrivateKey() *gost.PrivateKey {
    return this.privateKey
}

// 获取 PrivateKey 明文
func (this Gost) GetPrivateKeyBytes() []byte {
    privateKey := this.privateKey
    if privateKey == nil {
        return nil
    }

    return gost.PrivateKeyTo(privateKey)
}

// 获取 PublicKey
func (this Gost) GetPublicKey() *gost.PublicKey {
    return this.publicKey
}

// 获取 PublicKey 明文
func (this Gost) GetPublicKeyBytes() []byte {
    publicKey := this.publicKey
    if publicKey == nil {
        return nil
    }

    return gost.PublicKeyTo(publicKey)
}

// 获取 Curve
func (this Gost) GetCurve() *gost.Curve {
    return this.curve
}

// 获取 hash 类型
func (this Gost) GetSignHash() HashFunc {
    return this.signHash
}

// 获取 keyData
func (this Gost) GetKeyData() []byte {
    return this.keyData
}

// 获取 data
func (this Gost) GetData() []byte {
    return this.data
}

// 获取 parsedData
func (this Gost) GetParsedData() []byte {
    return this.parsedData
}

// 获取编码类型
func (this Gost) GetEncoding() EncodingType {
    return this.encoding
}

// 获取验证后情况
func (this Gost) GetVerify() bool {
    return this.verify
}

// 获取 secretData
func (this Gost) GetSecretData() []byte {
    return this.secretData
}

// 获取错误
func (this Gost) GetErrors() []error {
    return this.Errors
}
