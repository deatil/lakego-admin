package dh

import (
    "errors"
    "encoding/pem"
)

// 生成公钥
func (this Dh) MakePublicKey() Dh {
    this.publicKey = nil

    if this.privateKey == nil {
        err := errors.New("Dh: [MakePublicKey()] privateKey error.")
        return this.AppendError(err)
    }

    // 导出公钥
    this.publicKey = &this.privateKey.PublicKey

    return this
}

// 生成密钥 der 数据
func (this Dh) MakeKeyDer() Dh {
    var block *pem.Block
    if block, _ = pem.Decode(this.keyData); block == nil {
        err := errors.New("Dh: [MakeKeyDer()] keyData error.")
        return this.AppendError(err)
    }

    this.keyData = block.Bytes

    return this
}
