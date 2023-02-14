package rsa

import(
    "errors"
    "encoding/pem"
)

// 生成公钥
func (this Rsa) MakePublicKey() Rsa {
    this.publicKey = nil

    if this.privateKey == nil {
        err := errors.New("Rsa: [MakePublicKey()] privateKey error.")
        return this.AppendError(err)
    }

    this.publicKey = &this.privateKey.PublicKey

    return this
}

// 生成密钥 der 数据
func (this Rsa) MakeKeyDer() Rsa {
    var block *pem.Block
    if block, _ = pem.Decode(this.keyData); block == nil {
        err := errors.New("Rsa: [MakeKeyDer()] keyData error.")
        return this.AppendError(err)
    }

    this.keyData = block.Bytes

    return this
}
