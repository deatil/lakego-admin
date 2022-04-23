package cryptobin

import (
    "errors"
    "crypto/rand"
)

// 私钥签名
func (this SM2) Sign() SM2 {
    if this.privateKey == nil {
        this.Error = errors.New("privateKey error.")

        return this
    }

    this.paredData, this.Error = this.privateKey.Sign(rand.Reader, this.data, nil)

    return this
}

// 公钥验证
// 使用原始数据[data]对比签名后数据
func (this SM2) Very(data []byte) SM2 {
    if this.publicKey == nil {
        this.Error = errors.New("publicKey error.")

        return this
    }

    this.veryed = this.publicKey.Verify(data, this.data)

    return this
}
