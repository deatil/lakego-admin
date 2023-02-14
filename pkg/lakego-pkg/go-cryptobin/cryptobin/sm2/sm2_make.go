package sm2

import(
    "errors"
    "encoding/pem"
)

// 生成公钥
func (this SM2) MakePublicKey() SM2 {
    this.publicKey = nil

    if this.privateKey == nil {
        err := errors.New("SM2: [MakePublicKey()] privateKey error.")
        return this.AppendError(err)
    }

    this.publicKey = &this.privateKey.PublicKey

    return this
}

// 生成密钥 der 数据
func (this SM2) MakeKeyDer() SM2 {
    var block *pem.Block
    if block, _ = pem.Decode(this.keyData); block == nil {
        err := errors.New("SM2: [MakeKeyDer()] keyData error.")
        return this.AppendError(err)
    }

    this.keyData = block.Bytes

    return this
}
