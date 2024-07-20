package sm2

import (
    "errors"
    "crypto/rand"

    "github.com/deatil/go-cryptobin/gm/sm2"
)

// 私钥签名
func (this SM2) Sign() SM2 {
    switch this.encoding {
        case EncodingASN1:
            return this.SignASN1()
        case EncodingBytes:
            return this.SignBytes()
    }

    return this.SignASN1()
}

// 公钥验证
// 使用原始数据[data]对比签名后数据
func (this SM2) Verify(data []byte) SM2 {
    switch this.encoding {
        case EncodingASN1:
            return this.VerifyASN1(data)
        case EncodingBytes:
            return this.VerifyBytes(data)
    }

    return this.VerifyASN1(data)
}

// ===============

// 私钥签名 ASN1
func (this SM2) SignASN1() SM2 {
    if this.privateKey == nil {
        err := errors.New("privateKey empty.")
        return this.AppendError(err)
    }

    parsedData, err := this.privateKey.Sign(rand.Reader, this.data, sm2.SignerOpts{
        Uid:  this.uid,
        Hash: this.signHash,
    })
    if err != nil {
        return this.AppendError(err)
    }

    this.parsedData = parsedData

    return this
}

// 公钥验证 ASN1
// 使用原始数据[data]对比签名后数据
func (this SM2) VerifyASN1(data []byte) SM2 {
    if this.publicKey == nil {
        err := errors.New("publicKey empty.")
        return this.AppendError(err)
    }

    this.verify = this.publicKey.Verify(data, this.data, sm2.SignerOpts{
        Uid:  this.uid,
        Hash: this.signHash,
    })

    return this
}

// ===============

// 私钥签名 Bytes
// 兼容[招行]
func (this SM2) SignBytes() SM2 {
    if this.privateKey == nil {
        err := errors.New("privateKey empty.")
        return this.AppendError(err)
    }

    parsedData, err := this.privateKey.SignBytes(rand.Reader, this.data, sm2.SignerOpts{
        Uid:  this.uid,
        Hash: this.signHash,
    })
    if err != nil {
        return this.AppendError(err)
    }

    this.parsedData = parsedData

    return this
}

// 公钥验证 Bytes
// 兼容[招行]
// 使用原始数据[data]对比签名后数据
func (this SM2) VerifyBytes(data []byte) SM2 {
    if this.publicKey == nil {
        err := errors.New("publicKey empty.")
        return this.AppendError(err)
    }

    if len(this.data) != 64 {
        err := errors.New("sig data error.")
        return this.AppendError(err)
    }

    this.verify = this.publicKey.VerifyBytes(data, this.data, sm2.SignerOpts{
        Uid:  this.uid,
        Hash: this.signHash,
    })

    return this
}
