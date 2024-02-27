package gost

import (
    "errors"
    "crypto/rand"

    "github.com/deatil/go-cryptobin/gost"
)

// 私钥签名
func (this Gost) Sign() Gost {
    if this.privateKey == nil {
        err := errors.New("privateKey empty.")
        return this.AppendError(err)
    }

    hashed, err := this.dataHash(this.data)
    if err != nil {
        return this.AppendError(err)
    }

    parsedData, err := gost.Sign(rand.Reader, this.privateKey, hashed)
    if err != nil {
        return this.AppendError(err)
    }

    this.parsedData = parsedData

    return this
}

// 公钥验证
// 使用原始数据[data]对比签名后数据
func (this Gost) Verify(data []byte) Gost {
    if this.publicKey == nil {
        err := errors.New("publicKey empty.")
        return this.AppendError(err)
    }

    hashed, err := this.dataHash(data)
    if err != nil {
        return this.AppendError(err)
    }

    this.verify, err = gost.Verify(this.publicKey, hashed, this.data)

    return this.AppendError(err)
}

// ===============

// 私钥签名
func (this Gost) SignASN1() Gost {
    if this.privateKey == nil {
        err := errors.New("privateKey empty.")
        return this.AppendError(err)
    }

    hashed, err := this.dataHash(this.data)
    if err != nil {
        return this.AppendError(err)
    }

    parsedData, err := gost.SignASN1(rand.Reader, this.privateKey, hashed)
    if err != nil {
        return this.AppendError(err)
    }

    this.parsedData = parsedData

    return this
}

// 公钥验证
// 使用原始数据[data]对比签名后数据
func (this Gost) VerifyASN1(data []byte) Gost {
    if this.publicKey == nil {
        err := errors.New("publicKey empty.")
        return this.AppendError(err)
    }

    hashed, err := this.dataHash(data)
    if err != nil {
        return this.AppendError(err)
    }

    this.verify, err = gost.VerifyASN1(this.publicKey, hashed, this.data)

    return this.AppendError(err)
}

// ===============

// 签名后数据
func (this Gost) dataHash(data []byte) ([]byte, error) {
    if this.signHash == nil {
        return nil, errors.New("hash func empty.")
    }

    h := this.signHash()
    h.Write(data)

    return h.Sum(nil), nil
}
