package rsa

import(
    "errors"
    "encoding/pem"
)

// 生成公钥
func (this RSA) MakePublicKey() RSA {
    this.publicKey = nil

    if this.privateKey == nil {
        err := errors.New("go-cryptobin/rsa: privateKey empty.")
        return this.AppendError(err)
    }

    this.publicKey = &this.privateKey.PublicKey

    return this
}

// 生成密钥 der 数据
func (this RSA) MakeKeyDer() RSA {
    var block *pem.Block
    if block, _ = pem.Decode(this.keyData); block == nil {
        err := errors.New("go-cryptobin/rsa: keyData error.")
        return this.AppendError(err)
    }

    this.keyData = block.Bytes

    return this
}
