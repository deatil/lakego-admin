package gost

import (
    "errors"
    "crypto/rand"

    "github.com/deatil/go-cryptobin/pubkey/gost"
)

// 私钥签名
// privateKey Sign
func (this Gost) Sign() Gost {
    switch this.encoding {
        case EncodingASN1:
            return this.SignASN1()
        case EncodingBytes:
            return this.SignBytes()
    }

    return this.SignBytes()
}

// 公钥验证
// 使用原始数据[data]对比签名后数据
// publicKey Verify
func (this Gost) Verify(data []byte) Gost {
    switch this.encoding {
        case EncodingASN1:
            return this.VerifyASN1(data)
        case EncodingBytes:
            return this.VerifyBytes(data)
    }

    return this.VerifyBytes(data)
}

// ===============

// 私钥签名
// privateKey Sign with asn.1
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
// publicKey Verify with asn.1
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

// 私钥签名
// privateKey Sign with bytes
func (this Gost) SignBytes() Gost {
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
// publicKey Verify with bytes
func (this Gost) VerifyBytes(data []byte) Gost {
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

// 签名数据
// sign data with hash
func (this Gost) dataHash(data []byte) ([]byte, error) {
    if this.signHash == nil {
        return nil, errors.New("hash func empty.")
    }

    h := this.signHash()
    h.Write(data)

    return h.Sum(nil), nil
}
