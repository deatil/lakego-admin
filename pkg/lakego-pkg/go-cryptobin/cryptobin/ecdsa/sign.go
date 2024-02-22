package ecdsa

import (
    "errors"
    "math/big"
    "crypto/rand"
    "crypto/ecdsa"
)

// 私钥签名
func (this ECDSA) Sign() ECDSA {
    if this.privateKey == nil {
        err := errors.New("privateKey error.")
        return this.AppendError(err)
    }

    hashed, err := this.dataHash(this.data)
    if err != nil {
        return this.AppendError(err)
    }

    parsedData, err := ecdsa.SignASN1(rand.Reader, this.privateKey, hashed)
    if err != nil {
        return this.AppendError(err)
    }

    this.parsedData = parsedData

    return this.AppendError(err)
}

// 公钥验证
// 使用原始数据[data]对比签名后数据
func (this ECDSA) Verify(data []byte) ECDSA {
    if this.publicKey == nil {
        err := errors.New("publicKey error.")
        return this.AppendError(err)
    }

    hashed, err := this.dataHash(data)
    if err != nil {
        return this.AppendError(err)
    }

    this.verify = ecdsa.VerifyASN1(this.publicKey, hashed, this.data)

    return this
}

// ===============

// 私钥签名 ASN1
func (this ECDSA) SignASN1() ECDSA {
    return this.Sign()
}

// 公钥验证 ASN1
// 使用原始数据[data]对比签名后数据
func (this ECDSA) VerifyASN1(data []byte) ECDSA {
    return this.Verify(data)
}

// ===============

// 私钥签名 Bytes
func (this ECDSA) SignBytes() ECDSA {
    if this.privateKey == nil {
        err := errors.New("privateKey error.")
        return this.AppendError(err)
    }

    hashed, err := this.dataHash(this.data)
    if err != nil {
        return this.AppendError(err)
    }

    r, s, err := ecdsa.Sign(rand.Reader, this.privateKey, hashed)
    if err != nil {
        return this.AppendError(err)
    }

    byteLen := (this.privateKey.Curve.Params().BitSize + 7) / 8

    buf := make([]byte, 2*byteLen)

    r.FillBytes(buf[      0:  byteLen])
    s.FillBytes(buf[byteLen:2*byteLen])

    this.parsedData = buf

    return this.AppendError(err)
}

// 公钥验证 Bytes
// 使用原始数据[data]对比签名后数据
func (this ECDSA) VerifyBytes(data []byte) ECDSA {
    if this.publicKey == nil {
        err := errors.New("publicKey error.")
        return this.AppendError(err)
    }

    hashed, err := this.dataHash(data)
    if err != nil {
        return this.AppendError(err)
    }

    byteLen := (this.publicKey.Curve.Params().BitSize + 7) / 8
    if len(this.data) != 2*byteLen {
        err := errors.New("sig data error.")
        return this.AppendError(err)
    }

    sign := this.data

    r := new(big.Int).SetBytes(sign[      0:  byteLen])
    s := new(big.Int).SetBytes(sign[byteLen:2*byteLen])

    this.verify = ecdsa.Verify(this.publicKey, hashed, r, s)

    return this
}

// ===============

// 签名后数据
func (this ECDSA) dataHash(data []byte) ([]byte, error) {
    if this.signHash == nil {
        return nil, errors.New("Hash func not set.")
    }

    h := this.signHash()
    h.Write(data)

    return h.Sum(nil), nil
}
