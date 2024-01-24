package ecdsa

import(
    "errors"
    "encoding/pem"
)

// 生成公钥
func (this Ecdsa) MakePublicKey() Ecdsa {
    this.publicKey = nil

    if this.privateKey == nil {
        err := errors.New("Ecdsa: privateKey error.")
        return this.AppendError(err)
    }

    this.publicKey = &this.privateKey.PublicKey

    return this
}

// 生成密钥 der 数据
func (this Ecdsa) MakeKeyDer() Ecdsa {
    var block *pem.Block
    if block, _ = pem.Decode(this.keyData); block == nil {
        err := errors.New("Ecdsa: keyData error.")
        return this.AppendError(err)
    }

    this.keyData = block.Bytes

    return this
}
