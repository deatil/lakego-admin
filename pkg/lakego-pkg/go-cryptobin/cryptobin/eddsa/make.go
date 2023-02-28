package eddsa

import (
    "errors"
    "crypto/ed25519"
    "encoding/pem"
)

// 生成公钥
func (this EdDSA) MakePublicKey() EdDSA {
    this.publicKey = ed25519.PublicKey{}

    if this.privateKey == nil {
        err := errors.New("EdDSA: [MakePublicKey()] privateKey error.")
        return this.AppendError(err)
    }

    // 导出公钥
    this.publicKey = this.privateKey.Public().(ed25519.PublicKey)

    return this
}

// 生成密钥 der 数据
func (this EdDSA) MakeKeyDer() EdDSA {
    var block *pem.Block
    if block, _ = pem.Decode(this.keyData); block == nil {
        err := errors.New("EdDSA: [MakeKeyDer()] keyData error.")
        return this.AppendError(err)
    }

    this.keyData = block.Bytes

    return this
}
