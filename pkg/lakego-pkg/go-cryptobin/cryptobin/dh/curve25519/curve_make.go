package curve25519

import (
    "errors"
    "encoding/pem"
)

// 生成公钥
func (this Curve25519) MakePublicKey() Curve25519 {
    this.publicKey = nil

    if this.privateKey == nil {
        err := errors.New("Curve25519: [MakePublicKey()] privateKey error.")
        return this.AppendError(err)
    }

    // 导出公钥
    this.publicKey = &this.privateKey.PublicKey

    return this
}

// 生成密钥 der 数据
func (this Curve25519) MakeKeyDer() Curve25519 {
    var block *pem.Block
    if block, _ = pem.Decode(this.keyData); block == nil {
        err := errors.New("Curve25519: [MakeKeyDer()] keyData error.")
        return this.AppendError(err)
    }

    this.keyData = block.Bytes

    return this
}
