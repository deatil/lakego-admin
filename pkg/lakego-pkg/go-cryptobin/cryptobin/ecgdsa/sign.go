package ecgdsa

import (
    "errors"
    "crypto/rand"

    "github.com/deatil/go-cryptobin/pubkey/ecgdsa"
)

// 私钥签名
func (this ECGDSA) Sign() ECGDSA {
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
func (this ECGDSA) Verify(data []byte) ECGDSA {
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
func (this ECGDSA) SignASN1() ECGDSA {
    if this.privateKey == nil {
        err := errors.New("privateKey empty.")
        return this.AppendError(err)
    }

    if this.signHash == nil {
        err := errors.New("Hash func not set.")
        return this.AppendError(err)
    }

    sig, err := ecgdsa.Sign(rand.Reader, this.privateKey, this.signHash, this.data)
    if err != nil {
        return this.AppendError(err)
    }

    this.parsedData = sig

    return this.AppendError(err)
}


// 公钥验证 ASN1
// 使用原始数据[data]对比签名后数据
func (this ECGDSA) VerifyASN1(data []byte) ECGDSA {
    if this.publicKey == nil {
        err := errors.New("publicKey empty.")
        return this.AppendError(err)
    }

    if this.signHash == nil {
        err := errors.New("Hash func not set.")
        return this.AppendError(err)
    }

    this.verify = ecgdsa.Verify(this.publicKey, this.signHash, data, this.data)

    return this
}


// ===============

// 私钥签名 Bytes
func (this ECGDSA) SignBytes() ECGDSA {
    if this.privateKey == nil {
        err := errors.New("privateKey empty.")
        return this.AppendError(err)
    }

    if this.signHash == nil {
        err := errors.New("Hash func not set.")
        return this.AppendError(err)
    }

    sig, err := ecgdsa.SignBytes(rand.Reader, this.privateKey, this.signHash, this.data)
    if err != nil {
        return this.AppendError(err)
    }

    this.parsedData = sig

    return this.AppendError(err)
}

// 公钥验证 Bytes
// 使用原始数据[data]对比签名后数据
func (this ECGDSA) VerifyBytes(data []byte) ECGDSA {
    if this.publicKey == nil {
        err := errors.New("publicKey empty.")
        return this.AppendError(err)
    }

    if this.signHash == nil {
        err := errors.New("Hash func not set.")
        return this.AppendError(err)
    }

    this.verify = ecgdsa.VerifyBytes(this.publicKey, this.signHash, data, this.data)

    return this
}
