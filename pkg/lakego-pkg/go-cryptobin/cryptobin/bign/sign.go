package bign

import (
    "errors"
    "crypto/rand"

    "github.com/deatil/go-cryptobin/pubkey/bign"
)

// 私钥签名
func (this Bign) Sign() Bign {
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
func (this Bign) Verify(data []byte) Bign {
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
func (this Bign) SignASN1() Bign {
    if this.privateKey == nil {
        err := errors.New("go-cryptobin/bign: privateKey empty.")
        return this.AppendError(err)
    }

    if this.signHash == nil {
        err := errors.New("go-cryptobin/bign: Hash func not set.")
        return this.AppendError(err)
    }

    sig, err := bign.Sign(rand.Reader, this.privateKey, this.signHash, this.data, this.adata)
    if err != nil {
        return this.AppendError(err)
    }

    this.parsedData = sig

    return this.AppendError(err)
}


// 公钥验证 ASN1
// 使用原始数据[data]对比签名后数据
func (this Bign) VerifyASN1(data []byte) Bign {
    if this.publicKey == nil {
        err := errors.New("go-cryptobin/bign: publicKey empty.")
        return this.AppendError(err)
    }

    if this.signHash == nil {
        err := errors.New("go-cryptobin/bign: Hash func not set.")
        return this.AppendError(err)
    }

    this.verify = bign.Verify(this.publicKey, this.signHash, data, this.adata, this.data)

    return this
}


// ===============

// 私钥签名 Bytes
func (this Bign) SignBytes() Bign {
    if this.privateKey == nil {
        err := errors.New("go-cryptobin/bign: privateKey empty.")
        return this.AppendError(err)
    }

    if this.signHash == nil {
        err := errors.New("go-cryptobin/bign: Hash func not set.")
        return this.AppendError(err)
    }

    sig, err := bign.SignBytes(rand.Reader, this.privateKey, this.signHash, this.data, this.adata)
    if err != nil {
        return this.AppendError(err)
    }

    this.parsedData = sig

    return this.AppendError(err)
}

// 公钥验证 Bytes
// 使用原始数据[data]对比签名后数据
func (this Bign) VerifyBytes(data []byte) Bign {
    if this.publicKey == nil {
        err := errors.New("go-cryptobin/bign: publicKey empty.")
        return this.AppendError(err)
    }

    if this.signHash == nil {
        err := errors.New("go-cryptobin/bign: Hash func not set.")
        return this.AppendError(err)
    }

    this.verify = bign.VerifyBytes(this.publicKey, this.signHash, data, this.adata, this.data)

    return this
}
