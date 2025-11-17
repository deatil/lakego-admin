package bip0340

import(
    "errors"
    "encoding/pem"
)

// 生成公钥
func (this BIP0340) MakePublicKey() BIP0340 {
    this.publicKey = nil

    if this.privateKey == nil {
        err := errors.New("go-cryptobin/bip0340: privateKey empty.")
        return this.AppendError(err)
    }

    this.publicKey = &this.privateKey.PublicKey

    return this
}

// 生成密钥 der 数据
func (this BIP0340) MakeKeyDer() BIP0340 {
    var block *pem.Block
    if block, _ = pem.Decode(this.keyData); block == nil {
        err := errors.New("go-cryptobin/bip0340: keyData error.")
        return this.AppendError(err)
    }

    this.keyData = block.Bytes

    return this
}
