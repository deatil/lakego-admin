package elgamal

import (
    "errors"
    "encoding/pem"
)

// 生成公钥
func (this EIGamal) MakePublicKey() EIGamal {
    this.publicKey = nil

    if this.privateKey == nil {
        err := errors.New("privateKey error.")
        return this.AppendError(err)
    }

    // 导出公钥
    this.publicKey = &this.privateKey.PublicKey

    return this
}

// 生成密钥 der 数据
func (this EIGamal) MakeKeyDer() EIGamal {
    var block *pem.Block
    if block, _ = pem.Decode(this.keyData); block == nil {
        err := errors.New("keyData error.")
        return this.AppendError(err)
    }

    this.keyData = block.Bytes

    return this
}
