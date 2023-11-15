package elgamal

import (
    "errors"
    "crypto/rand"

    "github.com/deatil/go-cryptobin/elgamal"
)

// 私钥签名
func (this EIGamal) Sign() EIGamal {
    if this.privateKey == nil {
        err := errors.New("elgamal: privateKey error.")
        return this.AppendError(err)
    }

    hashed, err := this.DataHash(this.signHash, this.data)
    if err != nil {
        return this.AppendError(err)
    }

    parsedData, err := elgamal.SignASN1(rand.Reader, this.privateKey, hashed)
    if err != nil {
        return this.AppendError(err)
    }

    this.parsedData = parsedData

    return this.AppendError(err)
}

// 公钥验证
// 使用原始数据[data]对比签名后数据
func (this EIGamal) Verify(data []byte) EIGamal {
    if this.publicKey == nil {
        err := errors.New("elgamal: publicKey error.")
        return this.AppendError(err)
    }

    hashed, err := this.DataHash(this.signHash, data)
    if err != nil {
        return this.AppendError(err)
    }

    this.verify, err = elgamal.VerifyASN1(this.publicKey, hashed, this.data)
    if err != nil {
        return this.AppendError(err)
    }

    return this
}

// 签名后数据
func (this EIGamal) DataHash(fn HashFunc, data []byte) ([]byte, error) {
    h := fn()
    h.Write(data)

    return h.Sum(nil), nil
}
