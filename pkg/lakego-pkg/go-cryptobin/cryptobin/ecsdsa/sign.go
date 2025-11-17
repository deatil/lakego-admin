package ecsdsa

import (
    "errors"
    "crypto/rand"

    "github.com/deatil/go-cryptobin/pubkey/ecsdsa"
)

// 私钥签名
func (this ECSDSA) Sign() ECSDSA {
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
func (this ECSDSA) Verify(data []byte) ECSDSA {
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
func (this ECSDSA) SignASN1() ECSDSA {
    if this.privateKey == nil {
        err := errors.New("go-cryptobin/ecsdsa: privateKey empty.")
        return this.AppendError(err)
    }

    if this.signHash == nil {
        err := errors.New("go-cryptobin/ecsdsa: Hash func not set.")
        return this.AppendError(err)
    }

    sig, err := ecsdsa.Sign(rand.Reader, this.privateKey, this.signHash, this.data)
    if err != nil {
        return this.AppendError(err)
    }

    this.parsedData = sig

    return this.AppendError(err)
}


// 公钥验证 ASN1
// 使用原始数据[data]对比签名后数据
func (this ECSDSA) VerifyASN1(data []byte) ECSDSA {
    if this.publicKey == nil {
        err := errors.New("go-cryptobin/ecsdsa: publicKey empty.")
        return this.AppendError(err)
    }

    if this.signHash == nil {
        err := errors.New("go-cryptobin/ecsdsa: Hash func not set.")
        return this.AppendError(err)
    }

    this.verify = ecsdsa.Verify(this.publicKey, this.signHash, data, this.data)

    return this
}


// ===============

// 私钥签名 Bytes
func (this ECSDSA) SignBytes() ECSDSA {
    if this.privateKey == nil {
        err := errors.New("go-cryptobin/ecsdsa: privateKey empty.")
        return this.AppendError(err)
    }

    if this.signHash == nil {
        err := errors.New("go-cryptobin/ecsdsa: Hash func not set.")
        return this.AppendError(err)
    }

    sig, err := ecsdsa.SignBytes(rand.Reader, this.privateKey, this.signHash, this.data)
    if err != nil {
        return this.AppendError(err)
    }

    this.parsedData = sig

    return this.AppendError(err)
}

// 公钥验证 Bytes
// 使用原始数据[data]对比签名后数据
func (this ECSDSA) VerifyBytes(data []byte) ECSDSA {
    if this.publicKey == nil {
        err := errors.New("go-cryptobin/ecsdsa: publicKey empty.")
        return this.AppendError(err)
    }

    if this.signHash == nil {
        err := errors.New("go-cryptobin/ecsdsa: Hash func not set.")
        return this.AppendError(err)
    }

    this.verify = ecsdsa.VerifyBytes(this.publicKey, this.signHash, data, this.data)

    return this
}
