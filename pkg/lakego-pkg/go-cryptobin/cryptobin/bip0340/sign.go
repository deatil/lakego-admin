package bip0340

import (
    "errors"
    "crypto/rand"

    "github.com/deatil/go-cryptobin/pubkey/bip0340"
)

// 私钥签名
func (this BIP0340) Sign() BIP0340 {
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
func (this BIP0340) Verify(data []byte) BIP0340 {
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
func (this BIP0340) SignASN1() BIP0340 {
    if this.privateKey == nil {
        err := errors.New("privateKey empty.")
        return this.AppendError(err)
    }

    if this.signHash == nil {
        err := errors.New("Hash func not set.")
        return this.AppendError(err)
    }

    sig, err := bip0340.Sign(rand.Reader, this.privateKey, this.signHash, this.data)
    if err != nil {
        return this.AppendError(err)
    }

    this.parsedData = sig

    return this.AppendError(err)
}


// 公钥验证 ASN1
// 使用原始数据[data]对比签名后数据
func (this BIP0340) VerifyASN1(data []byte) BIP0340 {
    if this.publicKey == nil {
        err := errors.New("publicKey empty.")
        return this.AppendError(err)
    }

    if this.signHash == nil {
        err := errors.New("Hash func not set.")
        return this.AppendError(err)
    }

    this.verify = bip0340.Verify(this.publicKey, this.signHash, data, this.data)

    return this
}


// ===============

// 私钥签名 Bytes
func (this BIP0340) SignBytes() BIP0340 {
    if this.privateKey == nil {
        err := errors.New("privateKey empty.")
        return this.AppendError(err)
    }

    if this.signHash == nil {
        err := errors.New("Hash func not set.")
        return this.AppendError(err)
    }

    sig, err := bip0340.SignBytes(rand.Reader, this.privateKey, this.signHash, this.data)
    if err != nil {
        return this.AppendError(err)
    }

    this.parsedData = sig

    return this.AppendError(err)
}

// 公钥验证 Bytes
// 使用原始数据[data]对比签名后数据
func (this BIP0340) VerifyBytes(data []byte) BIP0340 {
    if this.publicKey == nil {
        err := errors.New("publicKey empty.")
        return this.AppendError(err)
    }

    if this.signHash == nil {
        err := errors.New("Hash func not set.")
        return this.AppendError(err)
    }

    this.verify = bip0340.VerifyBytes(this.publicKey, this.signHash, data, this.data)

    return this
}
