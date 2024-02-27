package ed448

import (
    "errors"
    "encoding/pem"

    "github.com/deatil/go-cryptobin/ed448"
)

// 生成公钥
func (this ED448) MakePublicKey() ED448 {
    this.publicKey = ed448.PublicKey{}

    if this.privateKey == nil {
        err := errors.New("privateKey empty.")
        return this.AppendError(err)
    }

    // 导出公钥
    this.publicKey = this.privateKey.Public().(ed448.PublicKey)

    return this
}

// 生成密钥 der 数据
func (this ED448) MakeKeyDer() ED448 {
    var block *pem.Block
    if block, _ = pem.Decode(this.keyData); block == nil {
        err := errors.New("keyData error.")
        return this.AppendError(err)
    }

    this.keyData = block.Bytes

    return this
}
